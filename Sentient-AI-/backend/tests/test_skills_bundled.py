"""Tests for the bundled skills in backend/skills/ (spec §7): every skill
folder loads ``ok`` with no finding of either severity, manifest.json is
exactly what ``python -m scripts.skills_manifest`` writes, each SKILL.md
keeps the size caps and the house layout, every tool, capability and
connector a skill names exists, a read loads every tool its Workflow calls
(or the step says tools.find loads it), a skill declares the tools it hands
off to or writes with through tools.find, a few playbook claims match what
the tools do, each skill's text passes the prompt guard section by section
and as the skills.read result the runtime scans, the <available_skills>
block for all of them fits its cap without cutting a description, and
CREDITS.md has an entry for each.

Why it exists: a bundled skill is text the model follows as a playbook. One
edited without re-pinning goes ``changed`` and quietly stops being offered;
one that names a tool that does not exist, or that a read leaves out of the
offer, leaves the model guessing; one whose wording trips the runtime's
prompt guard is redacted out of the skills.read result, so the model gets
an empty playbook; and a description cut to fit the block loses the "Use
when" words the model picks a skill by. These checks fail the pull request
instead of the user's turn.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from services import capabilities as capability_registry
from services.agent.context_manager import core_tool_names
from services.agent.prompt_guard import PromptGuard
from services.agent.runtime import AgentRuntime, LoadedTools, RuntimePromptGuard
from services.agent.tool_registry import BUILTIN_CONNECTOR_TYPES, CONNECTOR_CATALOG
from services.connectors import registry as connector_registry
from services.connectors.definition import ActionCategory
from services.skills.loader import (
    MANIFEST_PATH,
    MAX_REFERENCE_BYTES,
    MAX_SKILL_BYTES,
    SKILLS_ROOT,
    SkillCatalog,
    SkillRecord,
    load_skills,
    split_sections,
)
from services.skills.manifest import compute_manifest, render_manifest
from services.skills.prompt import (
    SKILLS_BLOCK_CHAR_CAP,
    SKILLS_BLOCK_FOOTER,
    SKILLS_BLOCK_HEADER,
    render_available_skills,
)
from services.tools.skills import SkillsToolkit

BACKEND = Path(__file__).resolve().parents[1]

# The ten skills spec §7 ships in v1. More may be added; none of these may go.
V1_SKILLS = frozenset(
    {
        "github",
        "goals",
        "google-workspace",
        "inbox-triage",
        "meal-planner",
        "school-week-planner",
        "shopping",
        "skill-vetter",
        "travel-planning",
        "wide-research",
    }
)

# Every skill folder on disk (the loader skips "_template" and dotfolders).
SKILL_NAMES = sorted(
    entry.name
    for entry in SKILLS_ROOT.iterdir()
    if entry.is_dir() and not entry.name.startswith(("_", "."))
)

# The body headings every bundled playbook has, in this order (README.md).
SECTIONS = ("Purpose", "When to use", "Workflow", "Output", "Rules")
# A bundled description says what the skill does and when to use it, in at
# most this many characters (the prompt block shows each one whole).
MAX_DESCRIPTION_CHARS = 400
VERSION = "1.0.0"

# A "type.action" name written in a playbook's prose.
TOOL_MENTION = re.compile(r"\b([a-z][a-z0-9_]*)\.([a-z][a-z0-9_]*)\b")
# Tool families a playbook may name that are not in the catalog of every
# build: goals.* and skills.* are built-in families of this feature.
FEATURE_FAMILIES = frozenset({"goals", "skills"})
# A playbook step that needs a tool a read does not load says to load it
# with this tool, in the same sentence.
FIND_TOOL = "tools.find"
# Where one sentence of a playbook ends (a tool name never has a space
# after its dot).
SENTENCE_END = re.compile(r"(?<=[.!?])\s+")


@pytest.fixture(scope="module")
def catalog() -> SkillCatalog:
    return load_skills()


def bundled(catalog: SkillCatalog, name: str) -> SkillRecord:
    record = catalog.get(name)
    assert record is not None, f"{name} did not load"
    return record


def texts(record: SkillRecord) -> dict[str, str]:
    """The Markdown the model can read: SKILL.md's body and each reference."""
    return {"SKILL.md": record.body, **record.references}


def catalog_tools() -> set[str]:
    return {f"{kind}.{spec.action}" for kind, specs in CONNECTOR_CATALOG.items() for spec in specs}


def section(record: SkillRecord, heading: str) -> str:
    """The text under *heading* in SKILL.md, with its line breaks and
    indents folded into single spaces."""
    text = next(part["text"] for part in split_sections(record.body) if part["heading"] == heading)
    return " ".join(text.split())


def sentences(text: str) -> list[str]:
    return SENTENCE_END.split(" ".join(text.split()))


def connector_sets(record: SkillRecord) -> list[frozenset[str]]:
    """The single-connector sets the skill's requires allows: one per
    connector type it requires or, when it requires none, no connector at
    all and each connector type it names on its own."""
    if record.requires_connectors:
        return [frozenset({kind}) for kind in record.requires_connectors]
    named = {match.group(1) for match in TOOL_MENTION.finditer(record.body)}
    named.update(tool.partition(".")[0] for tool in record.tools)
    kinds = sorted((named & set(CONNECTOR_CATALOG)) - set(BUILTIN_CONNECTOR_TYPES))
    return [frozenset(), *(frozenset({kind}) for kind in kinds)]


def turn_tools(connectors: frozenset[str]) -> list[dict[str, str]]:
    """A turn's full tool list with *connectors* connected and every
    capability on (a capability that is off only removes names, which moves
    the rest forward)."""
    return [
        {"name": f"{kind}.{spec.action}"}
        for kind, specs in CONNECTOR_CATALOG.items()
        if kind in BUILTIN_CONNECTOR_TYPES or kind in connectors
        for spec in specs
    ]


def all_capabilities(records: list[SkillRecord]) -> set[str]:
    """Every registered capability, plus any a skill requires (whether those
    are registered is its own test)."""
    keys = set(capability_registry.keys())
    keys.update(key for record in records for key in record.requires_capabilities)
    return keys


# --------------------------------------------------------------------------- #
# Loading and pinning
# --------------------------------------------------------------------------- #


def test_every_v1_skill_is_bundled(catalog: SkillCatalog) -> None:
    assert V1_SKILLS <= set(SKILL_NAMES)
    assert set(catalog.names()) == set(SKILL_NAMES)
    assert "_template" not in catalog


@pytest.mark.parametrize("name", SKILL_NAMES)
def test_each_skill_loads_ok_with_no_finding(catalog: SkillCatalog, name: str) -> None:
    record = bundled(catalog, name)
    assert record.status == "ok", record.status_reason
    assert record.status_reason is None
    # Spec §7: no finding of either severity (external URLs would be listed
    # as warn findings, and none are expected).
    assert [finding.to_dict() for finding in record.findings] == []


def test_the_manifest_pins_exactly_the_bundled_skills(catalog: SkillCatalog) -> None:
    expected = compute_manifest(catalog)
    assert sorted(expected["skills"]) == SKILL_NAMES
    on_disk = MANIFEST_PATH.read_bytes().decode("utf-8")
    assert on_disk == render_manifest(expected), (
        "manifest.json is out of date: run python -m scripts.skills_manifest from backend/"
    )


def test_the_manifest_script_check_passes_without_the_apps_environment() -> None:
    clean = {"PATH": os.environ.get("PATH", "")}
    checked = subprocess.run(
        [sys.executable, "-m", "scripts.skills_manifest", "--check"],
        cwd=BACKEND,
        env=clean,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert checked.returncode == 0, checked.stderr
    # Warn findings would be printed before the verdict line.
    assert checked.stdout.strip().splitlines() == [
        f"{MANIFEST_PATH} is up to date ({len(SKILL_NAMES)} skills)."
    ]


# --------------------------------------------------------------------------- #
# Size, layout and frontmatter
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", SKILL_NAMES)
def test_each_skill_keeps_the_caps_and_the_house_layout(catalog: SkillCatalog, name: str) -> None:
    record = bundled(catalog, name)
    assert len((record.path / "SKILL.md").read_bytes()) <= MAX_SKILL_BYTES
    for relpath in record.reference_files:
        assert len((record.path / relpath).read_bytes()) <= MAX_REFERENCE_BYTES
    assert record.title != record.name
    assert record.version == VERSION
    assert record.category is not None
    assert len(record.description) <= MAX_DESCRIPTION_CHARS
    assert "Use when" in record.description
    headings = [section["heading"] for section in split_sections(record.body)]
    assert [heading for heading in headings if heading in SECTIONS] == list(SECTIONS)


def test_credits_has_an_entry_for_every_skill() -> None:
    credits = (SKILLS_ROOT / "CREDITS.md").read_text(encoding="utf-8")
    for name in SKILL_NAMES:
        assert f"\n## {name}\n" in credits, f"CREDITS.md has no section for {name}"


# --------------------------------------------------------------------------- #
# Tools, capabilities and connectors
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", SKILL_NAMES)
def test_every_listed_tool_exists_and_the_playbook_names_it(
    catalog: SkillCatalog, name: str
) -> None:
    record = bundled(catalog, name)
    known = catalog_tools()
    assert [tool for tool in record.tools if tool not in known] == []
    prose = "\n".join(texts(record).values())
    assert [tool for tool in record.tools if tool not in prose] == []


@pytest.mark.parametrize("name", SKILL_NAMES)
def test_every_tool_the_playbook_mentions_exists(catalog: SkillCatalog, name: str) -> None:
    record = bundled(catalog, name)
    known = catalog_tools()
    families = set(CONNECTOR_CATALOG) | FEATURE_FAMILIES
    unknown = sorted(
        {
            match.group(0)
            for text in texts(record).values()
            for match in TOOL_MENTION.finditer(text)
            if match.group(1) in families and match.group(0) not in known
        }
    )
    assert unknown == []


@pytest.mark.parametrize("name", SKILL_NAMES)
def test_a_read_loads_every_tool_the_workflow_calls(catalog: SkillCatalog, name: str) -> None:
    """A read loads the first MAX_SKILL_TOOL_LOADS listed tools the turn has
    that are not core (AgentRuntime._load_skill_tools, called here), and a
    tool that is neither loaded nor core may be trimmed from the offer. So
    for each connector set the skill allows, every tool its Workflow names
    is core, loaded, or named in a sentence that says to load it with
    tools.find. No listed tool is core: it is always offered, so listing
    one only hides the next name behind the cut. (A name past the cut is
    still the reach skills.scan_report declares.)"""
    record = bundled(catalog, name)
    core = core_tool_names()
    assert [tool for tool in record.tools if tool in core] == []
    workflow = sentences(section(record, "Workflow"))
    for connectors in connector_sets(record):
        schemas = turn_tools(connectors)
        offered = {schema["name"] for schema in schemas}
        read = {"ok": True, "tools": list(record.tools)}
        loaded = AgentRuntime._load_skill_tools(read, schemas, LoadedTools())["tools"]
        unloaded = sorted(
            {
                match.group(0)
                for sentence in workflow
                if FIND_TOOL not in sentence
                for match in TOOL_MENTION.finditer(sentence)
                if match.group(0) in offered
                and match.group(0) not in core
                and match.group(0) not in loaded
            }
        )
        assert unloaded == [], sorted(connectors)


@pytest.mark.asyncio
async def test_the_vetter_takes_reach_from_the_scan_report(catalog: SkillCatalog) -> None:
    """skills.read's ``tools`` is only what that read loaded for this turn,
    so the skill-vetter playbook takes a skill's reach from the scan
    report's ``declared_tools``, which for shopping includes the payment
    tool whatever this turn may use."""
    vetter = bundled(catalog, "skill-vetter")
    report = await SkillsToolkit(catalog=catalog).execute("scan_report", {"name": "shopping"})
    assert report["status"] == "ok"
    assert "browser.checkout" in report["declared_tools"]
    assert set(report["requires"]) == {"connectors", "capabilities"}
    workflow = section(vetter, "Workflow")
    assert "declared_tools" in workflow and "requires" in workflow
    reads = [s for s in sentences(workflow) if re.search(r"\bskills\.read\b(?!_)", s)]
    assert any("loaded for this turn" in sentence for sentence in reads)
    # Reading the vetted skill loads its tools into the conversation, so a
    # review reads it only on request.
    assert any("only when the owner asks" in sentence for sentence in reads)
    # A hand-off or a tools.find load widens reach, and the rating counts it.
    assert (
        "hands off to another skill" in workflow and "drives tools through tools.find" in workflow
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "drives"),
    [
        # Booking follows the shopping skill's site steps and its checkout.
        ("travel-planning", {"browser.act", "browser.checkout"}),
        # Writes are loaded with tools.find, past the read's load cut.
        (
            "github",
            {
                "github.comment",
                "github.create_issue",
                "github.merge_pr",
                "github.dispatch_workflow",
            },
        ),
    ],
)
async def test_the_scan_report_declares_what_a_skill_hands_off_or_finds(
    catalog: SkillCatalog, name: str, drives: set[str]
) -> None:
    """The skill-vetter takes reach from the scan report's declared_tools and
    rates a skill Low when they only read, so a skill that books through
    the shopping skill's checkout, or writes through tools.find, declares
    those tools: otherwise "can travel-planning spend money?" or "what can
    the github skill do?" gets a read-only answer."""
    report = await SkillsToolkit(catalog=catalog).execute("scan_report", {"name": name})
    assert report["status"] == "ok"
    assert drives <= set(report["declared_tools"])
    assert "only reads," not in section(bundled(catalog, name), "Purpose")


def test_a_skill_declares_what_the_skill_it_hands_off_to_changes(catalog: SkillCatalog) -> None:
    """A Workflow sentence that reads another skill with skills.read hands
    the work to that skill's steps, so every tool of the other skill that
    changes something (writes, deletes, runs or pays) is declared here too."""
    changes = {
        f"{kind}.{spec.action}"
        for kind, specs in CONNECTOR_CATALOG.items()
        for spec in specs
        if spec.category != ActionCategory.READ
    }
    missing: dict[str, list[str]] = {}
    for record in catalog:
        for sentence in sentences(section(record, "Workflow")):
            if not re.search(r"\bskills\.read\b(?!_)", sentence):
                continue
            for other in catalog:
                if other.name != record.name and f"the {other.name} skill" in sentence:
                    missing.setdefault(record.name, []).extend(
                        tool for tool in other.tools if tool in changes and tool not in record.tools
                    )
    assert "travel-planning" in missing  # the hand-off this test is about
    assert {name: tools for name, tools in missing.items() if tools} == {}


def test_the_meal_planner_promises_only_videos_with_captions(catalog: SkillCatalog) -> None:
    """video.transcript reads published captions (a YouTube video only on a
    provider that can watch it), so the playbook offers captioned videos,
    asks for the recipe when the transcript fails instead of guessing one,
    and keeps the shared rule to stop and say so when a step fails."""
    record = bundled(catalog, "meal-planner")
    assert "captioned videos" in record.description
    assert "cooking video" not in record.description
    step = [s for s in sentences(section(record, "Workflow")) if "video.transcript" in s]
    assert step and all("reel" not in sentence for sentence in step)
    assert "asks for the recipe text" in section(record, "Workflow")
    assert "- When a step fails, Crawler stops and says so" in section(record, "Rules")


def test_no_playbook_says_google_emails_new_guests(catalog: SkillCatalog) -> None:
    """google_workspace.create_event adds guests without asking Google to
    email them (microsoft.create_event's invitation goes out), so a
    playbook that says the Google event invites people leaves the user
    believing an invitation was sent when none was."""
    promises = re.compile(r"\b(?:sends?|emails?)\b[^.]*\binvit|\binvites\b", re.IGNORECASE)
    claims = [
        (record.name, sentence)
        for record in catalog
        for text in texts(record).values()
        for sentence in sentences(text)
        if "google_workspace.create_event" in sentence
        and promises.search(sentence)
        and not re.search(r"\bnot\b", sentence)
    ]
    assert claims == []
    workspace = section(bundled(catalog, "google-workspace"), "Workflow")
    assert "Google does not email them" in workspace


def test_every_required_capability_is_registered(catalog: SkillCatalog) -> None:
    registered = set(capability_registry.keys())
    missing = {
        record.name: [key for key in record.requires_capabilities if key not in registered]
        for record in catalog
    }
    assert {name: keys for name, keys in missing.items() if keys} == {}


def test_every_required_connector_is_a_real_connector_type(catalog: SkillCatalog) -> None:
    unknown = {
        record.name: [
            kind
            for kind in record.requires_connectors
            if not connector_registry.is_registered(kind) and kind not in CONNECTOR_CATALOG
        ]
        for record in catalog
    }
    assert {name: kinds for name, kinds in unknown.items() if kinds} == {}


# --------------------------------------------------------------------------- #
# The prompt guard, as the runtime applies it
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", SKILL_NAMES)
def test_every_section_passes_the_prompt_guard(catalog: SkillCatalog, name: str) -> None:
    """The runtime redacts list items one by one when a whole result is
    unsafe, so each section must pass on its own: as text, and as the item
    str() the runtime scans."""
    guard = PromptGuard()
    for relpath, text in texts(bundled(catalog, name)).items():
        for section in split_sections(text):
            for shown in (f"{section['heading']}\n{section['text']}", str(section)):
                result = guard.scan(shown)
                assert result.is_safe, (
                    relpath,
                    section["heading"],
                    result.threat_level.value,
                    [detection.pattern_name for detection in result.detections],
                )


@pytest.mark.asyncio
@pytest.mark.parametrize("name", SKILL_NAMES)
async def test_the_read_results_pass_the_runtime_guard(catalog: SkillCatalog, name: str) -> None:
    """skills.read and skills.read_reference results as spec §4.3 shapes
    them, scanned the way the runtime scans a tool result (str of the whole
    result). An exact {"safe": True} also rules out the guard failing open."""
    record = bundled(catalog, name)
    guard = RuntimePromptGuard()
    read = {
        "ok": True,
        "name": record.name,
        "title": record.title,
        "sha256": record.sha256,
        "sections": split_sections(record.body),
        "references": list(record.reference_files),
        "tools": list(record.tools),
    }
    assert await guard.scan_output(str(read), "test-user") == {"safe": True}
    for relpath, text in record.references.items():
        reference = {
            "ok": True,
            "name": record.name,
            "file": relpath,
            "sections": split_sections(text),
        }
        assert await guard.scan_output(str(reference), "test-user") == {"safe": True}


# --------------------------------------------------------------------------- #
# The <available_skills> block
# --------------------------------------------------------------------------- #


def test_the_block_lists_every_skill_with_its_whole_description(catalog: SkillCatalog) -> None:
    records = list(catalog)
    block = render_available_skills(
        records,
        enabled_capabilities=all_capabilities(records),
        connector_types=set(CONNECTOR_CATALOG),
    )
    assert block is not None
    assert block.startswith(f"{SKILLS_BLOCK_HEADER}\n")
    assert block.endswith(f"\n{SKILLS_BLOCK_FOOTER}")
    lines = block[len(SKILLS_BLOCK_HEADER) + 1 : -(len(SKILLS_BLOCK_FOOTER) + 1)]
    assert len(lines) <= SKILLS_BLOCK_CHAR_CAP
    # Nothing was cut: every description shows whole, so its "Use when"
    # words reach the model. A new skill that breaks this needs shorter
    # descriptions, not a bigger cap.
    assert lines.split("\n") == [
        f"- {record.name}: {' '.join(record.description.split())}"
        for record in sorted(records, key=lambda record: record.name)
    ]
