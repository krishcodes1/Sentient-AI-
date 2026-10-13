"""Controls what leaves for the AI provider: a floor that always masks keys,
passwords, card, bank and ID numbers, and (when the owner's switch is on and the
provider is not a local Ollama) placeholders for contact details that are put
back in what the model returns.

Why it exists: AgentRuntime._provider_complete is the one place a model is
asked, so applying ModelEgress there covers every source at once: the user's
messages, memories, tool results, documents, trigger payloads. The floor is
not a capability and cannot be switched off (backlog F6: "secrets never reach
logs, audit rows, error bodies or the model").

- ``outbound(messages)`` returns a scanned copy. Only text parts are read;
  image and audio parts pass through untouched. A part the detector cannot
  check is replaced by ``MODEL_WITHHELD``. Each text is scanned once per
  turn (a cache keyed by its sha256).
- ``inbound(response)`` restores placeholders in the reply and in every tool
  call's arguments, and remembers any placeholder this turn never minted
  (``unknown_placeholders``), which the runtime refuses.
- ``hidden_summary()`` counts, by label, the values hidden in messages new
  this turn (the latest user message and after), deduplicated by in-memory
  sha256 digests, for the turn's one ``sensitive_data_hidden`` audit row.

``current_egress`` holds the turn's ModelEgress while a turn runs; a model
call outside a turn gets a fresh floor-only one.
"""

from __future__ import annotations

import dataclasses
import hashlib
import ipaddress
from collections import Counter
from contextvars import ContextVar, Token
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import urlsplit

from services.security.policies import MODEL_FLOOR, MODEL_PERSONAL, MODEL_WITHHELD
from services.security.pseudonyms import PseudonymVault
from services.security.redact import findings, mask, redact_text

# The <privacy> block the system prompt gains while contact details are
# being hidden (AgentRuntime._with_system_prompt(privacy=True)). It shows no
# placeholder literally: text shaped like one is neutralised on the way out.
PRIVACY_SYSTEM_PROMPT = """\
<privacy>
Crawler replaced the user's contact details (email addresses, phone numbers,
street addresses, birth dates) with placeholders before this conversation
reached you: a kind and a number in double square brackets, like
[[EMAIL_n@domain]] (the address's domain is kept), [[PHONE_n]], [[ADDRESS_n]]
or [[DOB_n]]. Copy a placeholder exactly, brackets included, wherever its value
belongs, in replies and in tool arguments: Crawler puts the real value back
before anything is shown or sent. Never guess, reconstruct or ask for the
real value. Text marked [hidden by Crawler: ...] was a key, password, card or
ID number and is gone for good: never ask for it or work around it; when a
task needs it, tell the user to enter it themselves where it is needed.
</privacy>"""

# Loopback names an Ollama counts as local on; host.docker.internal is the
# computer the Docker install runs on. An Ollama on any other host (a LAN
# machine) counts as a cloud provider.
_LOCAL_HOST_NAMES = frozenset({"localhost", "host.docker.internal"})

TEXT_BLOCK = "text"
_WITHHELD_LABEL = "text Crawler could not check"


def is_local_provider(provider: str, ollama_base_url: str) -> bool:
    """True only for "ollama" on a loopback address, a *.localhost name or
    host.docker.internal."""
    if (provider or "").strip().lower() != "ollama":
        return False
    try:
        host = (urlsplit(ollama_base_url or "").hostname or "").lower().rstrip(".")
    except ValueError:
        return False
    if not host:
        return False
    if host in _LOCAL_HOST_NAMES or host.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_unspecified


async def hide_personal_for(
    gate: Optional[Callable[[], Awaitable[bool]]], provider: str, ollama_base_url: str
) -> bool:
    """Whether this turn hides contact details: the owner's switch is on
    (*gate*; unwired reads as off, a gate error as on) and the provider is
    not a local Ollama."""
    if gate is None or is_local_provider(provider, ollama_base_url):
        return False
    try:
        return bool(await gate())
    except Exception:  # noqa: BLE001 - a switch that cannot be read hides
        return True


def _digest(*parts: str) -> str:
    joined = "\x00".join(parts)
    return hashlib.sha256(joined.encode("utf-8", "surrogatepass")).hexdigest()


class ModelEgress:
    """The floor and the per-turn pseudonym vault for one turn."""

    def __init__(self, hide_personal: bool = False, *, first_new_index: Optional[int] = None) -> None:
        self.hide_personal = bool(hide_personal)
        self._vault: Optional[PseudonymVault] = PseudonymVault() if self.hide_personal else None
        self._first_new = first_new_index
        # sha256 of an original text -> (what the model sees, the digests
        # and labels of what was hidden in it).
        self._cache: dict[str, tuple[str, tuple[tuple[str, str], ...]]] = {}
        self._new_hidden: dict[str, str] = {}
        self._unknown: dict[str, list[str]] = {}
        self.withheld_parts = 0

    def __repr__(self) -> str:
        return (
            f"ModelEgress(hide_personal={self.hide_personal}, texts={len(self._cache)}, "
            f"hidden_new={len(self._new_hidden)})"
        )

    # ── outbound ──────────────────────────────────────────────────────

    def _transform(self, text: str) -> tuple[str, tuple[tuple[str, str], ...]]:
        hidden: list[tuple[str, str]] = []
        try:
            found = findings(text, MODEL_FLOOR)
            for finding in found:
                hidden.append((finding.label, _digest(finding.label, text[finding.start : finding.end])))
            masked, _ = mask(text, found, MODEL_FLOOR.placeholder)
            if self._vault is not None:
                masked, swapped = self._vault.hide_and_list(masked)
                hidden.extend((label, _digest(label, value)) for label, value in swapped)
        except Exception:  # noqa: BLE001 - fail closed: withhold the part
            self.withheld_parts += 1
            return MODEL_WITHHELD, ((_WITHHELD_LABEL, _digest("withheld", text)),)
        return masked, tuple(hidden)

    def _text(self, text: str, new: bool) -> str:
        key = _digest(text)
        cached = self._cache.get(key)
        if cached is None:
            cached = self._transform(text)
            self._cache[key] = cached
        shown, hidden = cached
        if new:
            for label, digest in hidden:
                self._new_hidden.setdefault(digest, label)
        return shown

    def _block(self, block: Any, new: bool) -> Any:
        if isinstance(block, dict) and block.get("type") == TEXT_BLOCK and isinstance(block.get("text"), str):
            copy = dict(block)
            copy["text"] = self._text(block["text"], new)
            return copy
        return block

    def outbound(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """A copy of *messages* as the provider may see it: the floor
        always, placeholders for contact details when hiding. Only text is
        read; other parts pass through as they are."""
        if self._first_new is None:
            self._first_new = next(
                (
                    i
                    for i in range(len(messages) - 1, -1, -1)
                    if isinstance(messages[i], dict) and messages[i].get("role") == "user"
                ),
                0,
            )
        out: list[dict[str, Any]] = []
        for index, message in enumerate(messages):
            if not isinstance(message, dict):
                out.append(message)
                continue
            new = index >= self._first_new
            copy = dict(message)
            content = message.get("content")
            if isinstance(content, str):
                copy["content"] = self._text(content, new)
            elif isinstance(content, list):
                copy["content"] = [self._block(block, new) for block in content]
            out.append(copy)
        return out

    # ── inbound ───────────────────────────────────────────────────────

    def inbound(self, response: Any) -> Any:
        """*response* (an LLMResponse) with this turn's placeholders put back
        in its text and in every tool call's arguments. Placeholders this
        turn never minted are left as they are and recorded per call."""
        vault = self._vault
        if vault is None or not dataclasses.is_dataclass(response) or isinstance(response, type):
            return response
        content = getattr(response, "content", None)
        if isinstance(content, str):
            content = vault.restore_text(content)
        calls: list[Any] = []
        for call in getattr(response, "tool_calls", None) or []:
            if not dataclasses.is_dataclass(call) or isinstance(call, type):
                calls.append(call)
                continue
            arguments, unknown = vault.restore_obj(getattr(call, "arguments", None))
            call_id = str(getattr(call, "id", ""))
            if unknown:
                self._unknown[call_id] = unknown
            else:
                # Providers that number calls per response (Gemini's
                # gemini_0, a remote Ollama's ollama_0) reuse ids every
                # round: a clean call must not inherit an earlier refusal.
                self._unknown.pop(call_id, None)
            calls.append(dataclasses.replace(call, arguments=arguments))
        return dataclasses.replace(response, content=content, tool_calls=calls)

    def unknown_placeholders(self, tool_call_id: str) -> list[str]:
        """Placeholders in that call's arguments this turn never minted."""
        return list(self._unknown.get(str(tool_call_id), ()))

    def restore_text(self, text: str) -> str:
        """*text* with this turn's placeholders put back."""
        return self._vault.restore_text(text) if self._vault is not None else text

    # ── what was hidden ───────────────────────────────────────────────

    def hidden_summary(self) -> dict[str, int]:
        """Distinct values hidden from the provider in this turn's new
        messages, counted by label. Labels only, never values."""
        return dict(Counter(self._new_hidden.values()))


current_egress: ContextVar[Optional[ModelEgress]] = ContextVar("crawler_model_egress", default=None)


class bind_egress:  # noqa: N801 - used like a function: `with bind_egress(egress):`
    """Makes *egress* the current turn's for the ``with`` (or ``async
    with``) block, and puts back what was there before on the way out,
    whether the block returns or raises."""

    def __init__(self, egress: ModelEgress) -> None:
        self.egress = egress
        self._token: Optional[Token[Optional[ModelEgress]]] = None

    def __enter__(self) -> ModelEgress:
        self._token = current_egress.set(self.egress)
        return self.egress

    def __exit__(self, *_exc: object) -> None:
        if self._token is not None:
            current_egress.reset(self._token)
            self._token = None

    async def __aenter__(self) -> ModelEgress:
        return self.__enter__()

    async def __aexit__(self, *exc: object) -> None:
        self.__exit__(*exc)


def redact_for_model(text: str) -> str:
    """*text* with the floor applied (keys, passwords, card, bank and ID
    numbers masked), for a caller that builds model input outside a turn.
    A detector error gives ``MODEL_WITHHELD``."""
    return redact_text(text, MODEL_FLOOR).text


def redact_for_embedding(text: str, *, cloud: bool, hide_personal: bool) -> str:
    """*text* as it may go to an embedding endpoint: the floor always, and
    contact details as [email], [phone], [address] or [birth date] (never
    restored) when the endpoint is a cloud one and the owner hides
    personal details. A detector error gives ``MODEL_WITHHELD``."""
    floored = redact_text(text, MODEL_FLOOR)
    if floored.withheld or not (cloud and hide_personal):
        return floored.text
    return redact_text(floored.text, MODEL_PERSONAL).text


__all__ = [
    "PRIVACY_SYSTEM_PROMPT",
    "ModelEgress",
    "bind_egress",
    "current_egress",
    "hide_personal_for",
    "is_local_provider",
    "redact_for_embedding",
    "redact_for_model",
]
