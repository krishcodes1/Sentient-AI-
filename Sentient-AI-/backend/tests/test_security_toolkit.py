"""Tests for the security.* built-in family (services/tools/security_checks.py
and its executor entry): they prove that an action no skill registered is
refused with a plain sentence and runs nothing, that a handler that raises
answers a fixed failure and only its error type is logged, that the
executor's user id and approval (never the model's) reach the handler, that
use_file_reputation registers both S10 file tools and keeps the toolkit for
the upload card's hooks, and that the upload's card hooks refuse it before any
card while file checks are not wired and go to the file reputation toolkit
once they are.

Why it exists: two security skills (S3's scam check, S10's file checks) answer
actions of one family that WAVE 0 wires before either skill exists. The
dispatcher must fail closed for an unregistered action, never leak a
handler's message (it could quote a scam text), and keep the upload, the one
WRITE, behind its own approval card with its own refusal policy.
"""

from __future__ import annotations

import json
from typing import Any, Optional

import pytest

from models.audit import AuditStatus
from services.agent import runtime as runtime_mod
from services.agent.runtime import PrecheckRefusal
from services.agent.tool_registry import (
    FILE_REPUTATION_RULE_POLICY,
    ConnectorToolExecutor,
    security_toolkit_of,
)
from services.audit import _EVENT_STATUS, redact_tool_arguments
from services.tools import security_checks
from services.tools.security_checks import CHECK_FAILED, NOT_AVAILABLE, SecurityToolkit

USER = "security-user"
SHA = "a" * 64


class FakeFileReputation:
    """Records what the S10 toolkit is asked, and answers as scripted."""

    def __init__(self, *, precheck: Optional[dict[str, Any]] = None) -> None:
        self.calls: list[tuple[str, str, dict[str, Any], str, Any]] = []
        self._precheck = precheck

    async def execute(self, action, params, user_id, *, approved=False):
        self.calls.append(("execute", action, dict(params), user_id, approved))
        return {"ok": True, "action": action, "approved": approved}

    async def precheck(self, action, params, user_id):
        self.calls.append(("precheck", action, dict(params), user_id, None))
        return self._precheck

    async def bind(self, action, params, user_id):
        self.calls.append(("bind", action, dict(params), user_id, None))
        return {"sha256": params.get("sha256"), "_upload": {"sha256": params.get("sha256"), "name": "a.exe"}}

    def describe(self, action, params, user_id):
        self.calls.append(("describe", action, dict(params), user_id, None))
        return "Send a.exe to VirusTotal to be scanned"


@pytest.mark.asyncio
async def test_an_unknown_action_is_refused_with_a_plain_sentence_and_runs_nothing():
    toolkit = SecurityToolkit()
    ran: list[str] = []

    async def handler(params, user_id, *, approved=False):
        ran.append(user_id)
        return {"ok": True}

    toolkit.register("check_scam", handler)
    assert await toolkit.execute("check_file", {"sha256": SHA}, USER) == {"ok": False, "error": NOT_AVAILABLE}
    assert ran == []
    # A bare executor's family has no handler at all: every action is refused.
    executor = ConnectorToolExecutor()
    result = await executor.execute("security.check_scam", {"text": "Pay now"}, USER)
    assert result == {"ok": False, "error": NOT_AVAILABLE}


@pytest.mark.asyncio
async def test_a_handler_that_raises_answers_a_fixed_failure_and_logs_only_its_type(monkeypatch):
    logged: list[tuple[str, dict[str, Any]]] = []

    class Recorder:
        def error(self, event, **fields):
            logged.append((event, fields))

    monkeypatch.setattr(security_checks, "logger", Recorder())
    toolkit = SecurityToolkit()

    async def boom(params, user_id, *, approved=False):
        raise ValueError("the scam text: send 500 to evil@example.com")

    async def not_a_dict(params, user_id, *, approved=False):
        return "ok"

    toolkit.register("check_scam", boom)
    toolkit.register("check_file", not_a_dict)
    assert await toolkit.execute("check_scam", {"text": "x"}, USER) == {"ok": False, "error": CHECK_FAILED}
    assert await toolkit.execute("check_file", {}, USER) == {"ok": False, "error": CHECK_FAILED}
    assert logged[0] == ("security_check_failed", {"action": "check_scam", "error_type": "ValueError"})
    assert "evil@example.com" not in repr(logged)


@pytest.mark.asyncio
async def test_the_executors_user_id_and_approval_reach_the_handler_never_the_models():
    seen: list[tuple[dict[str, Any], str, bool]] = []

    async def handler(params, user_id, *, approved=False):
        seen.append((params, user_id, approved))
        return {"ok": True, "verdict": "no_signs_found"}

    executor = ConnectorToolExecutor()
    assert security_toolkit_of(executor) is executor.security_toolkit
    security_toolkit_of(executor).register("check_scam", handler)
    result = await executor.execute(
        "security.check_scam", {"text": "Pay now", "user_id": "someone-else"}, USER
    )
    assert result == {"ok": True, "verdict": "no_signs_found"}
    assert seen == [({"text": "Pay now", "user_id": "someone-else"}, USER, False)]
    # A toolkit handed in is the one the family dispatches to.
    own = SecurityToolkit()
    assert ConnectorToolExecutor(security_toolkit=own).security_toolkit is own


@pytest.mark.asyncio
async def test_use_file_reputation_registers_both_file_tools_and_keeps_the_toolkit_for_card_hooks():
    executor = ConnectorToolExecutor()
    toolkit = security_toolkit_of(executor)
    assert toolkit.file_reputation is None
    fake = FakeFileReputation()
    toolkit.use_file_reputation(fake)
    assert toolkit.file_reputation is fake

    looked_up = await executor.execute("security.check_file", {"sha256": SHA}, USER)
    assert looked_up == {"ok": True, "action": "check_file", "approved": False}
    # The upload is a WRITE: unapproved, the executor refuses it before the toolkit.
    unapproved = await executor.execute("security.upload_to_virustotal", {"sha256": SHA}, USER)
    assert unapproved["ok"] is False and unapproved["requires_approval"] is True
    assert "sends a file to VirusTotal" in unapproved["error"]
    approved = await executor.execute(
        "security.upload_to_virustotal", {"sha256": SHA}, USER, approved=True
    )
    assert approved == {"ok": True, "action": "upload_to_virustotal", "approved": True}
    assert [(c[0], c[1], c[4]) for c in fake.calls] == [
        ("execute", "check_file", False),
        ("execute", "upload_to_virustotal", True),
    ]


@pytest.mark.asyncio
async def test_the_upload_is_refused_before_any_card_while_file_checks_are_not_wired():
    executor = ConnectorToolExecutor()
    arguments = {"sha256": SHA}
    refusal = executor.precheck_approval("security.upload_to_virustotal", arguments, USER)
    assert isinstance(refusal, PrecheckRefusal)
    assert refusal.policy == FILE_REPUTATION_RULE_POLICY
    assert refusal.rule == "unavailable" and refusal.result["refused"] is True
    assert "not set up" in refusal.reason
    bound = await executor.approval_arguments_async(
        "security.upload_to_virustotal", arguments, USER, task_id=None
    )
    assert bound["refused"] is True and bound["rule"] == "unavailable"
    assert executor.describe_approval("security.upload_to_virustotal", arguments, USER) is None
    # The runtime files a bind refusal of the upload under the same policy.
    assert runtime_mod._BIND_REFUSAL_POLICIES["security.upload_to_virustotal"] == FILE_REPUTATION_RULE_POLICY


@pytest.mark.asyncio
async def test_the_upload_card_hooks_go_to_the_file_reputation_toolkit():
    executor = ConnectorToolExecutor()
    fake = FakeFileReputation()
    security_toolkit_of(executor).use_file_reputation(fake)
    arguments = {"sha256": SHA, "user_confirmed": True}

    pending = executor.precheck_approval("security.upload_to_virustotal", arguments, USER)
    assert await pending is None
    bound = await executor.approval_arguments_async(
        "security.upload_to_virustotal", arguments, USER, task_id="t1"
    )
    assert bound["_upload"]["name"] == "a.exe"
    sentence = executor.describe_approval("security.upload_to_virustotal", bound, USER)
    assert sentence == "Send a.exe to VirusTotal to be scanned"
    # The model's user_confirmed never reaches the toolkit.
    assert all("user_confirmed" not in call[2] for call in fake.calls)
    assert [c[0] for c in fake.calls] == ["precheck", "bind", "describe"]

    refusing = FakeFileReputation(
        precheck={"ok": False, "rule": "already_known", "error": "VirusTotal already knows this file."}
    )
    other = ConnectorToolExecutor()
    security_toolkit_of(other).use_file_reputation(refusing)
    refusal = await other.precheck_approval("security.upload_to_virustotal", {"sha256": SHA}, USER)
    assert isinstance(refusal, PrecheckRefusal)
    assert (refusal.policy, refusal.rule) == (FILE_REPUTATION_RULE_POLICY, "already_known")
    assert refusal.reason == "VirusTotal already knows this file."
    # Other security actions have no card hooks.
    assert other.precheck_approval("security.check_file", {"sha256": SHA}, USER) is None
    assert other.describe_approval("security.check_file", {"sha256": SHA}, USER) is None


def test_audit_rows_keep_only_lengths_and_counts_of_a_scam_check_and_no_upload_facts():
    scam = redact_tool_arguments(
        "security.check_scam",
        {
            "text": "Your account is limited, confirm now",
            "urls": ["https://paypa1.example/login", "https://bit.ly/x"],
            "sender": "PayPal <service@paypa1.example>",
            "reply_to": "help@paypa1.example",
        },
    )
    assert scam == {
        "text": "<36 characters>",
        "urls": "<2 items>",
        "sender": "<31 characters>",
        "reply_to": "<19 characters>",
    }
    upload = redact_tool_arguments(
        "security__1a2b3c4d.upload_to_virustotal",
        {"sha256": SHA, "_upload": {"sha256": SHA, "name": "salary-2026.xlsx", "size_bytes": 10}},
    )
    assert upload["sha256"] == SHA and "salary" not in json.dumps(upload)
    # The security wave's own rows are registered: none falls through to blocked.
    for event, status in {
        "service_key_updated": AuditStatus.approved,
        "scam_check_ran": AuditStatus.approved,
        "scam_check_refused": AuditStatus.blocked,
        "file_reputation_uploaded": AuditStatus.approved,
        "file_reputation_upload_refused": AuditStatus.blocked,
        "file_reputation_key_rejected": AuditStatus.blocked,
        "mcp_tool_changed": AuditStatus.blocked,
        "site_rule_blocked": AuditStatus.blocked,
        "call_check_escalated": AuditStatus.pending,
    }.items():
        assert _EVENT_STATUS[event] == status, event
