"""Works out Canvas course grades in plain Python: the current grade, the grade
with hypothetical ("what-if") scores applied, and the score still needed on the
remaining work to reach a target percentage.

Why it exists: Weighted averages with drop rules are exactly the arithmetic a
language model gets wrong, so canvas.grade_whatif hands the model finished
numbers instead of raw assignment groups. This module does no I/O: it takes the
JSON Canvas returned and gives back a compact dict, so every rule here is
unit-tested without a network or a Canvas account.

The rules follow Canvas's own grade calculator:

- An assignment counts unless it is excused, omitted from the final grade,
  ungraded ("not_graded"), or unpublished. The current grade leaves ungraded
  work out; the "ungraded as zero" figure counts it as 0 points.
- Drop rules (drop_lowest, drop_highest, never_drop) pick the set of scores
  that gives the best group grade, then the worst for drop_highest, exactly
  as Canvas does. That is not "drop the smallest score": a 5/10 is dropped
  before a 40/100 only when that raises the group's percentage.
- Weighted courses combine group percentages by weight. Groups with no points
  counted are left out and the remaining weights are scaled up to 100 when
  they add up to less; weights above 100 are not scaled down. Unweighted
  courses divide total points by total points possible.
"""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Optional

# "Reached the target" tolerance: grades are sums of float quotients.
_EPS = 1e-9

MAX_WHAT_IF = 25
_MAX_REF_CHARS = 200
_MAX_SCORE_POINTS = 100_000.0
_MAX_PERCENT = 200.0
_NAME_CHARS = 40
_COURSE_CHARS = 60
_MAX_GROUPS_SHOWN = 8
_MAX_CANDIDATES = 5
# The executor adds its own envelope and the runtime cuts a connector result
# at 2000 characters, dropping the middle. Staying under this keeps every
# number intact.
RESULT_CHAR_LIMIT = 1600


class GradeInputError(ValueError):
    """An argument or payload the planner cannot use. The message names the
    problem in words the model can pass on; it never carries credentials."""


# ---------------------------------------------------------------------------
# Parsed course
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Assignment:
    id: str
    name: str
    points_possible: float
    # None: not graded yet, not posted to the student, or awaiting review.
    score: Optional[float]
    excused: bool = False
    # False: omitted from the final grade, not graded, or unpublished.
    counts: bool = True
    # Graded, but the score is not posted to the student yet.
    hidden: bool = False
    pending_review: bool = False


@dataclass(frozen=True)
class Group:
    id: str
    name: str
    weight: float
    assignments: tuple[Assignment, ...]
    drop_lowest: int = 0
    drop_highest: int = 0
    never_drop: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Course:
    groups: tuple[Group, ...]
    weighted: bool
    name: str = ""
    hide_final_grades: bool = False
    # Canvas's own current score from the enrollment, when it is visible.
    canvas_current: Optional[float] = None

    def assignments(self) -> list[Assignment]:
        return [a for g in self.groups for a in g.assignments]


@dataclass(frozen=True)
class GroupTotal:
    score: float
    possible: float
    counted: int
    dropped: int


def _number(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        out = float(value)
    elif isinstance(value, str):
        try:
            out = float(value.strip())
        except ValueError:
            return None
    else:
        return None
    return out if math.isfinite(out) else None


def _count(value: Any) -> int:
    number = _number(value)
    if number is None or number < 0:
        return 0
    return min(int(number), 1000)


def _ident(value: Any) -> str:
    if value is None or isinstance(value, bool):
        return ""
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    return str(value).strip()[:_MAX_REF_CHARS]


def _text(value: Any, limit: int = _NAME_CHARS) -> str:
    text = " ".join(str(value).split()) if value is not None else ""
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _norm(text: str) -> str:
    return " ".join(text.split()).casefold()


def _parse_assignment(raw: Any) -> Optional[Assignment]:
    if not isinstance(raw, Mapping):
        return None
    ident = _ident(raw.get("id"))
    if not ident:
        return None
    submission = raw.get("submission")
    sub: Mapping[str, Any] = submission if isinstance(submission, Mapping) else {}
    state = str(sub.get("workflow_state") or "")
    excused = sub.get("excused") is True
    score = _number(sub.get("score"))
    pending = state == "pending_review"
    if pending:
        # Canvas leaves a score awaiting review out of the current grade.
        score = None
    counts = (
        raw.get("omit_from_final_grade") is not True
        and raw.get("grading_type") != "not_graded"
        and raw.get("published", True) is not False
    )
    return Assignment(
        id=ident,
        name=" ".join(str(raw.get("name") or f"Assignment {ident}").split()),
        points_possible=max(0.0, _number(raw.get("points_possible")) or 0.0),
        score=score,
        excused=excused,
        counts=counts,
        hidden=score is None and not excused and state == "graded",
        pending_review=pending,
    )


def _canvas_current(course: Mapping[str, Any]) -> Optional[float]:
    enrollments = course.get("enrollments")
    for enrollment in enrollments if isinstance(enrollments, list) else []:
        if not isinstance(enrollment, Mapping):
            continue
        kind = str(enrollment.get("type") or enrollment.get("role") or "").lower()
        if kind in ("student", "studentenrollment"):
            value = _number(enrollment.get("computed_current_score"))
            if value is not None:
                return value
    return None


def parse_course(groups_payload: Any, course_payload: Any) -> Course:
    """Canvas's assignment groups (with assignments and the student's
    submissions) plus the course object, as a ``Course``. Malformed
    entries are skipped rather than guessed at."""
    course: Mapping[str, Any] = course_payload if isinstance(course_payload, Mapping) else {}
    groups: list[Group] = []
    seen: set[str] = set()
    for raw_group in groups_payload if isinstance(groups_payload, list) else []:
        if not isinstance(raw_group, Mapping):
            continue
        raw_rules = raw_group.get("rules")
        rules: Mapping[str, Any] = raw_rules if isinstance(raw_rules, Mapping) else {}
        never = rules.get("never_drop")
        raw_assignments = raw_group.get("assignments")
        assignments: list[Assignment] = []
        for raw in raw_assignments if isinstance(raw_assignments, list) else []:
            parsed = _parse_assignment(raw)
            if parsed is None or parsed.id in seen:
                continue
            seen.add(parsed.id)
            assignments.append(parsed)
        groups.append(
            Group(
                id=_ident(raw_group.get("id")),
                name=" ".join(str(raw_group.get("name") or "Assignments").split()),
                weight=max(0.0, _number(raw_group.get("group_weight")) or 0.0),
                assignments=tuple(assignments),
                drop_lowest=_count(rules.get("drop_lowest")),
                drop_highest=_count(rules.get("drop_highest")),
                never_drop=frozenset(
                    ident
                    for ident in (_ident(v) for v in (never if isinstance(never, list) else []))
                    if ident
                ),
            )
        )
    return Course(
        groups=tuple(groups),
        weighted=course.get("apply_assignment_group_weights") is True,
        name=_text(course.get("name") or course.get("course_code") or "", _COURSE_CHARS),
        hide_final_grades=course.get("hide_final_grades") is True,
        canvas_current=_canvas_current(course),
    )


# ---------------------------------------------------------------------------
# Drop rules (Canvas's algorithm)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Scored:
    id: str
    score: float
    possible: float


def _keep(
    items: list[_Scored], fixed: list[_Scored], keep: int, *, maximize: bool
) -> list[_Scored]:
    """The ``keep`` items of ``items`` that, together with ``fixed`` (never
    dropped), give the highest (``maximize``) or lowest group percentage.

    Canvas's method: for a trial percentage q, rank items by
    ``score - q * possible`` and take the best ``keep``; the sum over the
    kept and fixed items is non-negative exactly when some set reaches q.
    A bisection on q converges on the optimal set. It runs to float
    precision rather than Canvas's integer-score threshold, so half points
    are exact too.
    """
    keep = max(1, keep)
    if len(items) <= keep:
        return list(items)
    everything = [*items, *fixed]
    pointed = [i for i in everything if i.possible > 0]
    if not pointed:
        ordered = sorted(items, key=lambda i: i.score, reverse=maximize)
        return ordered[:keep]
    grades = [i.score / i.possible for i in pointed]
    smallest = min(i.possible for i in pointed)
    unpointed_up = sum(max(0.0, i.score) for i in everything if i.possible <= 0)
    unpointed_down = sum(max(0.0, -i.score) for i in everything if i.possible <= 0)
    q_low = min(grades) - unpointed_down / smallest
    q_high = max(grades) + unpointed_up / smallest

    def big_f(q: float) -> tuple[float, list[_Scored]]:
        rated = [(i.score - q * i.possible, n, i) for n, i in enumerate(items)]
        rated.sort(key=lambda r: ((-r[0] if maximize else r[0]), r[1]))
        chosen = rated[:keep]
        total = sum(r[0] for r in chosen) + sum(f.score - q * f.possible for f in fixed)
        return total, [r[2] for r in chosen]

    q_mid = (q_low + q_high) / 2
    total, kept = big_f(q_mid)
    for _ in range(100):
        if total < 0:
            q_high = q_mid
        else:
            q_low = q_mid
        following = (q_low + q_high) / 2
        if following in (q_low, q_high):
            break
        q_mid = following
        total, kept = big_f(q_mid)
    return kept


def _apply_drops(
    items: list[_Scored], drop_lowest: int, drop_highest: int, never_drop: frozenset[str]
) -> list[_Scored]:
    if not (drop_lowest or drop_highest):
        return items
    fixed = [i for i in items if i.id in never_drop]
    droppable = [i for i in items if i.id not in never_drop]
    n = len(droppable)
    if n == 0:
        return fixed
    # Canvas never drops every score: at least one droppable one stays.
    if drop_lowest >= n:
        drop_lowest, drop_highest = n - 1, 0
    if drop_highest >= n:
        drop_highest, drop_lowest = n - 1, 0
    keep_highest = n - drop_lowest
    keep_lowest = keep_highest - drop_highest
    kept = _keep(droppable, fixed, keep_highest, maximize=True)
    kept = _keep(kept, fixed, keep_lowest, maximize=False)
    return kept + fixed


# ---------------------------------------------------------------------------
# Grades
# ---------------------------------------------------------------------------


def group_total(
    group: Group, overrides: Mapping[str, float], *, ungraded_as_zero: bool = False
) -> GroupTotal:
    """Points earned and possible in one group after its drop rules."""
    items: list[_Scored] = []
    for a in group.assignments:
        if not a.counts or a.excused:
            continue
        score = overrides.get(a.id, a.score)
        if score is None:
            if not ungraded_as_zero:
                continue
            score = 0.0
        items.append(_Scored(a.id, score, a.points_possible))
    kept = _apply_drops(items, group.drop_lowest, group.drop_highest, group.never_drop)
    return GroupTotal(
        score=sum(i.score for i in kept),
        possible=sum(i.possible for i in kept),
        counted=len(kept),
        dropped=len(items) - len(kept),
    )


def course_percent(
    course: Course,
    overrides: Optional[Mapping[str, float]] = None,
    *,
    ungraded_as_zero: bool = False,
) -> Optional[float]:
    """The course grade in percent, unrounded; None when nothing counts."""
    scores = overrides or {}
    totals = [group_total(g, scores, ungraded_as_zero=ungraded_as_zero) for g in course.groups]
    if course.weighted:
        relevant = [
            (g.weight, t) for g, t in zip(course.groups, totals, strict=True) if t.possible > 0
        ]
        full_weight = sum(w for w, _ in relevant)
        if full_weight <= 0:
            return None
        grade = sum(t.score / t.possible * w for w, t in relevant)
        return grade * 100 / full_weight if full_weight < 100 else grade
    possible = sum(t.possible for t in totals)
    if possible <= 0:
        return None
    return sum(t.score for t in totals) / possible * 100


# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WhatIf:
    ref: str
    score: Optional[float] = None
    percent: Optional[float] = None


@dataclass(frozen=True)
class PlanRequest:
    what_if: tuple[WhatIf, ...] = ()
    target_percent: Optional[float] = None
    target_assignment: Optional[str] = None


_REF_KEYS = ("assignment", "assignment_id", "assignment_name", "name", "id")


def _percent_arg(value: Any, what: str) -> float:
    if isinstance(value, str):
        value = value.strip().rstrip("%").strip()
    number = _number(value)
    if number is None:
        raise GradeInputError(f"{what} must be a number, e.g. 87 for 87%.")
    if number < 0 or number > _MAX_PERCENT:
        raise GradeInputError(f"{what} must be between 0 and {_MAX_PERCENT:g}.")
    return number


def _ref_arg(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise GradeInputError(f"{what} needs an assignment id or name.")
    ref = " ".join(value.split()) if isinstance(value, str) else _ident(value)
    if not ref:
        raise GradeInputError(f"{what} needs an assignment id or name.")
    if len(ref) > _MAX_REF_CHARS:
        raise GradeInputError(f"{what} is too long; use the assignment id.")
    return ref


def _what_if_arg(raw: Any) -> tuple[WhatIf, ...]:
    if raw is None or raw == "" or raw == []:
        return ()
    if isinstance(raw, str):
        # Some models send an array argument as its JSON text.
        try:
            raw = json.loads(raw)
        except ValueError:
            raise GradeInputError(
                'what_if must be a list like [{"assignment": "Final Exam", "score": 85}].'
            )
    if isinstance(raw, Mapping):
        raw = [raw]
    if not isinstance(raw, list):
        raise GradeInputError("what_if must be a list of {assignment, score or percent}.")
    if len(raw) > MAX_WHAT_IF:
        raise GradeInputError(f"what_if takes at most {MAX_WHAT_IF} scores.")
    entries: list[WhatIf] = []
    for index, item in enumerate(raw, start=1):
        what = f"what_if entry {index}"
        if not isinstance(item, Mapping):
            raise GradeInputError(f"{what} must be an object with assignment and score or percent.")
        ref_value = next((item[k] for k in _REF_KEYS if item.get(k) not in (None, "")), None)
        ref = _ref_arg(ref_value, what)
        has_score = item.get("score") not in (None, "")
        has_percent = item.get("percent") not in (None, "")
        if has_score == has_percent:
            raise GradeInputError(f"{what} ({ref}) needs exactly one of score (points) or percent.")
        if has_score:
            score = _number(item.get("score"))
            if score is None or score < 0 or score > _MAX_SCORE_POINTS:
                raise GradeInputError(
                    f"{what} ({ref}): score must be a number of points, 0 or more."
                )
            entries.append(WhatIf(ref, score=score))
        else:
            entries.append(
                WhatIf(ref, percent=_percent_arg(item.get("percent"), f"{what} ({ref}) percent"))
            )
    return tuple(entries)


def parse_request(
    what_if: Any = None, target_percent: Any = None, target_assignment: Any = None
) -> PlanRequest:
    """Validate the tool's arguments before anything is fetched."""
    target: Optional[float] = None
    if target_percent not in (None, ""):
        target = _percent_arg(target_percent, "target_percent")
        if target <= 0:
            raise GradeInputError("target_percent must be more than 0.")
    solve_on: Optional[str] = None
    if target_assignment not in (None, ""):
        if target is None:
            raise GradeInputError("target_assignment is used with target_percent; give both.")
        solve_on = _ref_arg(target_assignment, "target_assignment")
    return PlanRequest(
        what_if=_what_if_arg(what_if), target_percent=target, target_assignment=solve_on
    )


def find_assignment(course: Course, ref: str) -> Assignment:
    """An assignment by id, exact name, or a unique part of its name
    (case-insensitive). Ambiguity is an error, never a guess."""
    everything = course.assignments()
    key = ref.strip()
    for a in everything:
        if a.id == key:
            return a
    wanted = _norm(key)
    exact = [a for a in everything if _norm(a.name) == wanted]
    if len(exact) == 1:
        return exact[0]
    candidates = exact or [a for a in everything if wanted and wanted in _norm(a.name)]
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise GradeInputError(
            f"No assignment in this course matches '{_text(ref)}'. "
            "Use an id or name from canvas.get_assignments."
        )
    listed = "; ".join(f"{_text(a.name)} (id {a.id})" for a in candidates[:_MAX_CANDIDATES])
    raise GradeInputError(
        f"'{_text(ref)}' matches {len(candidates)} assignments: {listed}. Use the assignment id."
    )


def _require_counting(a: Assignment) -> None:
    if a.excused:
        raise GradeInputError(
            f"'{_text(a.name)}' is excused, so it does not count toward the grade."
        )
    if not a.counts:
        raise GradeInputError(f"'{_text(a.name)}' does not count toward the final grade.")


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------


def _r(value: float) -> float | int:
    """Two decimals, and a whole number as an int (shorter JSON)."""
    rounded = round(value, 2)
    return int(rounded) if float(rounded).is_integer() else rounded


def _pct(value: Optional[float]) -> float | int | None:
    return None if value is None else _r(value)


def _ceil_hundredth(value: float) -> float:
    # The small allowance absorbs float noise such as 91.25000000000001.
    return math.ceil(value * 100 - 1e-6) / 100


def _solve(
    grade_at: Callable[[float], Optional[float]], target: float
) -> tuple[str, Optional[float], Optional[float]]:
    """The smallest fraction f in [0, 1] of the points possible that makes
    ``grade_at(f)`` reach ``target``, rounded up to 0.01%.

    Returns (status, needed_percent, best_percent) where status is
    "already met", "reachable", "not reachable" or "no grade".
    """
    best = grade_at(1.0)
    if best is None:
        return "no grade", None, None
    if best < target - _EPS:
        return "not reachable", None, best
    floor = grade_at(0.0)
    if floor is not None and floor >= target - _EPS:
        return "already met", 0.0, best
    low, high = 0.0, 1.0
    for _ in range(50):
        middle = (low + high) / 2
        grade = grade_at(middle)
        if grade is not None and grade >= target - _EPS:
            high = middle
        else:
            low = middle
    needed = min(100.0, _ceil_hundredth(high * 100))
    # Rounding up cannot lower the grade; this only guards float noise.
    while needed < 100.0:
        grade = grade_at(needed / 100)
        if grade is not None and grade >= target - _EPS:
            break
        needed = min(100.0, round(needed + 0.01, 2))
    return "reachable", needed, best


def _ungraded(course: Course, overrides: Mapping[str, float]) -> list[Assignment]:
    return [
        a
        for a in course.assignments()
        if a.counts
        and not a.excused
        and a.points_possible > 0
        and a.score is None
        and a.id not in overrides
    ]


def _target(
    course: Course,
    overrides: Mapping[str, float],
    request: PlanRequest,
    notes: list[str],
) -> dict[str, Any]:
    target = request.target_percent
    if target is None:
        return {}
    out: dict[str, Any] = {"target_percent": _r(target)}
    grade_at: Callable[[float], Optional[float]]

    if request.target_assignment is not None:
        chosen = find_assignment(course, request.target_assignment)
        _require_counting(chosen)
        if chosen.points_possible <= 0:
            raise GradeInputError(
                f"'{_text(chosen.name)}' is worth 0 points, so no score on it changes the grade."
            )
        if chosen.id in overrides:
            raise GradeInputError(
                f"'{_text(chosen.name)}' is in what_if and is target_assignment; "
                "leave it out of what_if to solve for it."
            )
        points = chosen.points_possible

        def on_one(fraction: float) -> Optional[float]:
            return course_percent(
                course, {**overrides, chosen.id: fraction * chosen.points_possible}
            )

        grade_at = on_one
        out["assignment"] = _text(chosen.name)
        out["points_possible"] = _r(chosen.points_possible)
        if chosen.score is not None:
            notes.append(
                f"'{_text(chosen.name)}' already has a score; the needed score replaces it."
            )
        others = [a for a in _ungraded(course, overrides) if a.id != chosen.id]
        if others:
            notes.append(
                f"{len(others)} other ungraded assignment(s) are left out; "
                "add them to what_if to count them."
            )
    else:
        remaining = _ungraded(course, overrides)
        if not remaining:
            final = course_percent(course, overrides)
            reached = final is not None and final >= target - _EPS
            out["remaining_assignments"] = 0
            out["status"] = "already met" if reached else "not reachable"
            out["final_percent"] = _pct(final)
            notes.append("No ungraded work is left, so the grade cannot change.")
            return out
        total_points = sum(a.points_possible for a in remaining)

        def on_all(fraction: float) -> Optional[float]:
            filled = {a.id: fraction * a.points_possible for a in remaining}
            return course_percent(course, {**overrides, **filled})

        grade_at = on_all
        out["remaining_assignments"] = len(remaining)
        out["remaining_points"] = _r(total_points)
        points = total_points
        notes.append(
            "Assumes the same percentage on every remaining assignment; "
            "work not yet in Canvas is not counted."
        )

    status, needed, best = _solve(grade_at, target)
    out["status"] = status
    if status == "not reachable":
        out["best_possible_percent"] = _pct(best)
    elif status == "no grade":
        notes.append("No course grade can be computed from the counted work.")
    elif needed is not None:
        out["needed_percent"] = _r(needed)
        key = "needed_points" if request.target_assignment is not None else "needed_points_total"
        out[key] = _r(needed / 100 * points)
    return out


def _group_rows(course: Course) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for group in course.groups:
        counting = [a for a in group.assignments if a.counts and not a.excused]
        if not counting and not (course.weighted and group.weight):
            continue
        total = group_total(group, {})
        row: dict[str, Any] = {"name": _text(group.name)}
        if course.weighted:
            row["weight"] = _r(group.weight)
        row["percent"] = _pct(total.score / total.possible * 100) if total.possible > 0 else None
        row["graded"] = sum(1 for a in counting if a.score is not None)
        left = sum(1 for a in counting if a.score is None and a.points_possible > 0)
        if left:
            row["left"] = left
        if total.dropped:
            row["dropped"] = total.dropped
        rows.append(row)
    return rows


def _notes(course: Course, current: Optional[float]) -> list[str]:
    notes = ["Estimate from your Canvas scores; Canvas's own grade is authoritative."]
    if course.weighted:
        empty = [g for g in course.groups if g.weight > 0 and group_total(g, {}).possible <= 0]
        if empty:
            names = ", ".join(_text(g.name, 24) for g in empty[:3])
            more = f" (+{len(empty) - 3} more)" if len(empty) > 3 else ""
            notes.append(
                f"Nothing is graded yet in {names}{more}; as Canvas does, that weight is "
                "left out and the other weights are scaled up to 100."
            )
        else:
            notes.append("Weighted by assignment group, as the course is set up.")
        total_weight = sum(g.weight for g in course.groups)
        if total_weight > 100 + _EPS:
            notes.append(
                f"Group weights add up to {_r(total_weight)}%; Canvas does not scale them down."
            )
    else:
        notes.append("The course does not weight groups, so the grade is total points.")
    notes.append("Ungraded, excused and not-counted work is left out of current_percent.")
    dropping = [g for g in course.groups if g.drop_lowest or g.drop_highest]
    if dropping:
        parts = []
        for g in dropping[:3]:
            rules = []
            if g.drop_lowest:
                rules.append(f"lowest {g.drop_lowest}")
            if g.drop_highest:
                rules.append(f"highest {g.drop_highest}")
            parts.append(f"{_text(g.name, 24)} drops {' and '.join(rules)}")
        more = f" (+{len(dropping) - 3} more)" if len(dropping) > 3 else ""
        notes.append("Drop rules applied as Canvas does: " + "; ".join(parts) + more + ".")
    counting = [a for a in course.assignments() if a.counts and not a.excused]
    hidden = sum(1 for a in counting if a.hidden)
    if hidden:
        notes.append(
            f"{hidden} score(s) are graded but not posted to you yet; they count as ungraded."
        )
    pending = sum(1 for a in counting if a.pending_review)
    if pending:
        notes.append(f"{pending} submission(s) await review; they count as ungraded.")
    if course.hide_final_grades:
        notes.append("The instructor hides course totals in Canvas.")
    if current is None:
        notes.append("Nothing graded counts yet, so there is no current grade.")
    if (
        course.canvas_current is not None
        and current is not None
        and abs(course.canvas_current - current) > 0.05
    ):
        notes.append(
            f"Canvas itself shows {_r(course.canvas_current)}%; the gap can come from "
            "grading periods or scores hidden from you."
        )
    return notes


def _size(result: Mapping[str, Any]) -> int:
    return len(json.dumps(result, ensure_ascii=False, separators=(",", ":")))


def _fit(result: dict[str, Any], limit: int = RESULT_CHAR_LIMIT) -> dict[str, Any]:
    """Trim the least important detail until the result fits ``limit``:
    group rows first, then what-if echoes, then the later assumptions.
    The headline numbers are never trimmed."""
    groups: list[dict[str, Any]] = result.get("groups", [])
    if len(groups) > _MAX_GROUPS_SHOWN:
        result["more_groups"] = len(groups) - _MAX_GROUPS_SHOWN
        del groups[_MAX_GROUPS_SHOWN:]
    while _size(result) > limit and len(groups) > 2:
        groups.pop()
        result["more_groups"] = result.get("more_groups", 0) + 1
    what_if = result.get("what_if")
    if isinstance(what_if, dict):
        echoed: list[Any] = what_if.get("scores", [])
        while _size(result) > limit and len(echoed) > 3:
            echoed.pop()
            what_if["more_scores"] = what_if.get("more_scores", 0) + 1
    notes: list[str] = result.get("assumptions", [])
    while _size(result) > limit and len(notes) > 3:
        notes.pop()
    return result


def plan(groups_payload: Any, course_payload: Any, request: PlanRequest) -> dict[str, Any]:
    """The compact answer canvas.grade_whatif returns: current grade, the
    what-if grade, the target solve, a group breakdown and assumptions."""
    course = parse_course(groups_payload, course_payload)
    if not course.assignments():
        raise GradeInputError("This course has no assignments visible to you in Canvas.")

    overrides: dict[str, float] = {}
    echoed: list[dict[str, Any]] = []
    for entry in request.what_if:
        chosen = find_assignment(course, entry.ref)
        _require_counting(chosen)
        if chosen.id in overrides:
            raise GradeInputError(f"'{_text(chosen.name)}' appears twice in what_if.")
        if entry.score is not None:
            score = entry.score
        else:
            if chosen.points_possible <= 0:
                raise GradeInputError(
                    f"'{_text(chosen.name)}' is worth 0 points; give score in points instead of percent."
                )
            score = (entry.percent or 0.0) / 100 * chosen.points_possible
        overrides[chosen.id] = score
        row: dict[str, Any] = {
            "assignment": _text(chosen.name),
            "score": _r(score),
            "of": _r(chosen.points_possible),
        }
        if chosen.score is not None:
            row["was"] = _r(chosen.score)
        echoed.append(row)

    current = course_percent(course)
    notes = _notes(course, current)
    result: dict[str, Any] = {}
    if course.name:
        result["course"] = course.name
    result["weighting"] = "group weights" if course.weighted else "total points"
    result["current_percent"] = _pct(current)
    if course.canvas_current is not None:
        result["canvas_current_percent"] = _pct(course.canvas_current)
    result["with_ungraded_as_zero_percent"] = _pct(course_percent(course, ungraded_as_zero=True))
    if overrides:
        result["what_if"] = {"percent": _pct(course_percent(course, overrides)), "scores": echoed}
    if request.target_percent is not None:
        result["target"] = _target(course, overrides, request, notes)
    result["groups"] = _group_rows(course)
    result["assumptions"] = notes
    return _fit(result)
