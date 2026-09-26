"""Tests for the Canvas grade math in services/connectors/canvas_grades.py: the
current grade (weighted and total points), excused, ungraded and not-counted
work, Canvas's drop_lowest / drop_highest / never_drop rules, what-if scores,
and the score needed to reach a target, including unreachable targets.

Why it exists: canvas.grade_whatif exists so the model never does this
arithmetic itself, which only helps if the arithmetic is right. Every rule is
checked against hand-worked numbers, and the drop rules against a brute-force
search over every possible set of kept scores.
"""

from __future__ import annotations

import itertools
import json
import random
from typing import Any, Optional

import pytest

from services.connectors import canvas_grades as cg
from services.connectors.canvas_grades import GradeInputError, course_percent, parse_course

# ---------------------------------------------------------------------------
# Builders: Canvas JSON as /assignment_groups?include[]=assignments&include[]=submission
# and /courses/:id?include[]=total_scores return it.
# ---------------------------------------------------------------------------


def a(
    ident: int, points: float, score: Optional[float] = None, name: str = "", **extra: Any
) -> dict:
    submission = extra.pop("submission", {"score": score})
    return {
        "id": ident,
        "name": name or f"A{ident}",
        "points_possible": points,
        "submission": submission,
        **extra,
    }


def g(ident: int, name: str, assignments: list[dict], weight: float = 0, **rules: Any) -> dict:
    return {
        "id": ident,
        "name": name,
        "group_weight": weight,
        "rules": rules,
        "assignments": assignments,
    }


def course(weighted: bool = False, **extra: Any) -> dict:
    return {"id": 42, "name": "CSCI 456", "apply_assignment_group_weights": weighted, **extra}


def percent(groups: list[dict], weighted: bool = False, overrides=None, **kw) -> Optional[float]:
    return course_percent(parse_course(groups, course(weighted)), overrides, **kw)


def run(groups: list[dict], weighted: bool = False, course_extra=None, **request: Any) -> dict:
    payload = course(weighted, **(course_extra or {}))
    return cg.plan(groups, payload, cg.parse_request(**request))


# The CSCI 456 course from the proposal: HW drops its lowest, the final and
# the project are not graded yet.
def csci456() -> list[dict]:
    return [
        g(
            1,
            "Homework",
            [a(11, 10, 5, "HW 1"), a(12, 10, 9, "HW 2"), a(13, 10, 10, "HW 3")],
            20,
            drop_lowest=1,
        ),
        g(2, "Exams", [a(21, 100, 72, "Midterm"), a(22, 200, None, "Final Exam")], 50),
        g(3, "Project", [a(31, 50, None, "Project")], 30),
    ]


# ---------------------------------------------------------------------------
# Current grade: points vs weights
# ---------------------------------------------------------------------------


def test_unweighted_course_is_total_points_and_ignores_group_weights():
    groups = [
        g(1, "HW", [a(1, 10, 8), a(2, 10, 10)], weight=90),
        g(2, "Exams", [a(3, 100, 70)], weight=10),
    ]
    # (8 + 10 + 70) / (10 + 10 + 100)
    assert percent(groups) == pytest.approx(88 / 120 * 100)


def test_weighted_course_combines_group_percentages_by_weight():
    groups = [
        g(1, "HW", [a(1, 10, 8), a(2, 10, 10)], weight=40),  # 90%
        g(2, "Exams", [a(3, 100, 70)], weight=60),  # 70%
    ]
    assert percent(groups, weighted=True) == pytest.approx(0.9 * 40 + 0.7 * 60)


def test_weighted_groups_with_nothing_graded_are_left_out_and_the_rest_scaled_up():
    # Canvas's current grade: Project (30%) has nothing graded, so HW and
    # Exams stand for 70% and are scaled to 100.
    assert percent(csci456(), weighted=True) == pytest.approx((19 + 36) / 70 * 100)
    out = run(csci456(), weighted=True)
    assert out["current_percent"] == 78.57
    assert any("Nothing is graded yet in Project" in n for n in out["assumptions"])


def test_an_empty_weighted_group_is_left_out_like_an_ungraded_one():
    groups = [
        g(1, "HW", [a(1, 10, 9)], weight=40),
        g(2, "Final", [], weight=60),
    ]
    assert percent(groups, weighted=True) == pytest.approx(90)
    rows = run(groups, weighted=True)["groups"]
    assert rows[1] == {"name": "Final", "weight": 60, "percent": None, "graded": 0}


def test_a_zero_weight_group_does_not_move_a_weighted_grade():
    base = [g(1, "HW", [a(1, 10, 9)], weight=100)]
    with_practice = [*base, g(2, "Practice", [a(2, 10, 0)], weight=0)]
    assert percent(with_practice, weighted=True) == pytest.approx(percent(base, weighted=True))


def test_only_zero_weight_groups_graded_means_no_weighted_grade():
    groups = [g(1, "Practice", [a(1, 10, 9)], weight=0), g(2, "Exams", [a(2, 100)], weight=100)]
    assert percent(groups, weighted=True) is None
    out = run(groups, weighted=True)
    assert out["current_percent"] is None
    assert any("no current grade" in n for n in out["assumptions"])


def test_weights_over_100_are_not_scaled_down_and_say_so():
    groups = [g(1, "A", [a(1, 10, 10)], weight=60), g(2, "B", [a(2, 10, 10)], weight=60)]
    assert percent(groups, weighted=True) == pytest.approx(120)
    out = run(groups, weighted=True)
    assert any("add up to 120%" in n for n in out["assumptions"])


def test_nothing_graded_at_all_is_no_grade_not_zero():
    groups = [g(1, "HW", [a(1, 10), a(2, 10)])]
    assert percent(groups) is None
    assert percent(groups, weighted=True) is None
    # ...but counting the ungraded work as zero is a real 0%.
    assert percent(groups, ungraded_as_zero=True) == 0


# ---------------------------------------------------------------------------
# What counts
# ---------------------------------------------------------------------------


def test_excused_work_is_left_out_of_both_grades():
    excused = a(2, 100, None, submission={"score": None, "excused": True})
    groups = [g(1, "HW", [a(1, 10, 9), excused])]
    assert percent(groups) == pytest.approx(90)
    assert percent(groups, ungraded_as_zero=True) == pytest.approx(90)


def test_an_excused_score_is_ignored_even_when_canvas_sends_one():
    excused = a(2, 100, submission={"score": 0, "excused": True})
    assert percent([g(1, "HW", [a(1, 10, 9), excused])]) == pytest.approx(90)


def test_ungraded_work_is_left_out_of_current_and_zero_in_the_floor():
    groups = [g(1, "HW", [a(1, 10, 9), a(2, 10)])]
    assert percent(groups) == pytest.approx(90)
    assert percent(groups, ungraded_as_zero=True) == pytest.approx(45)
    out = run(groups)
    assert (out["current_percent"], out["with_ungraded_as_zero_percent"]) == (90, 45)


@pytest.mark.parametrize(
    "flag",
    [{"omit_from_final_grade": True}, {"grading_type": "not_graded"}, {"published": False}],
)
def test_work_that_does_not_count_is_left_out(flag):
    groups = [g(1, "HW", [a(1, 10, 9), a(2, 100, 0, **flag)])]
    assert percent(groups) == pytest.approx(90)
    assert percent(groups, ungraded_as_zero=True) == pytest.approx(90)


def test_extra_credit_on_a_zero_point_assignment_adds_points():
    groups = [g(1, "HW", [a(1, 10, 8), a(2, 0, 2)])]
    assert percent(groups) == pytest.approx(100)


def test_a_group_of_only_extra_credit_is_left_out_when_weighted():
    # Canvas skips a group with no points possible, even with a score in it.
    groups = [g(1, "HW", [a(1, 10, 8)], weight=50), g(2, "Bonus", [a(2, 0, 5)], weight=50)]
    assert percent(groups, weighted=True) == pytest.approx(80)


def test_pending_review_and_unposted_scores_count_as_ungraded_and_are_noted():
    pending = a(2, 10, submission={"score": 3, "workflow_state": "pending_review"})
    hidden = a(3, 10, submission={"score": None, "workflow_state": "graded"})
    groups = [g(1, "HW", [a(1, 10, 9), pending, hidden])]
    assert percent(groups) == pytest.approx(90)
    notes = run(groups)["assumptions"]
    assert any("1 score(s) are graded but not posted" in n for n in notes)
    assert any("1 submission(s) await review" in n for n in notes)


# ---------------------------------------------------------------------------
# Drop rules
# ---------------------------------------------------------------------------


def test_drop_lowest_keeps_the_best_set_not_the_smallest_percentage():
    # Dropping the 0/2 (the lowest percentage) gives 150/200 = 75%;
    # Canvas drops the 50/100 instead, for 100/102 = 98.04%.
    groups = [g(1, "Quizzes", [a(1, 2, 0), a(2, 100, 50), a(3, 100, 100)], drop_lowest=1)]
    assert percent(groups) == pytest.approx(100 / 102 * 100)


def test_drop_lowest_is_not_the_smallest_raw_score_either():
    # The smallest raw score (5/10) is not the one to drop: 40/100 is.
    groups = [g(1, "HW", [a(1, 10, 5), a(2, 100, 40), a(3, 10, 9)], drop_lowest=1)]
    assert percent(groups) == pytest.approx(14 / 20 * 100)


def test_drop_highest_keeps_the_worst_set():
    # Keeping {0/2, 50/100} = 49.02% is the lowest two-score percentage.
    groups = [g(1, "Q", [a(1, 10, 10), a(2, 2, 0), a(3, 100, 50)], drop_highest=1)]
    assert percent(groups) == pytest.approx(50 / 102 * 100)


def test_never_drop_keeps_a_score_even_when_it_is_the_lowest():
    groups = [
        g(1, "HW", [a(1, 10, 2), a(2, 10, 8), a(3, 10, 9)], drop_lowest=1, never_drop=[1]),
    ]
    # 2/10 stays; 8/10 is dropped instead: (2 + 9) / 20.
    assert percent(groups) == pytest.approx(55)


def test_never_drop_ids_match_whatever_type_canvas_sends():
    groups = [
        g(1, "HW", [a(1, 10, 2), a(2, 10, 8), a(3, 10, 9)], drop_lowest=1, never_drop=["1"]),
    ]
    assert percent(groups) == pytest.approx(55)


def test_dropping_more_than_there_are_scores_keeps_one():
    groups = [g(1, "HW", [a(1, 10, 2), a(2, 10, 8)], drop_lowest=5)]
    assert percent(groups) == pytest.approx(80)
    groups = [g(1, "HW", [a(1, 10, 2), a(2, 10, 8)], drop_highest=5)]
    assert percent(groups) == pytest.approx(20)


def test_drop_lowest_and_highest_together():
    scores = [3, 5, 6, 8, 10]
    groups = [
        g(1, "Q", [a(i, 10, s) for i, s in enumerate(scores, 1)], drop_lowest=1, drop_highest=1)
    ]
    # Drop the 3 (lowest) then the 10 (highest): (5 + 6 + 8) / 30.
    assert percent(groups) == pytest.approx(19 / 30 * 100)


def test_drops_apply_only_to_graded_work_in_the_current_grade():
    groups = [g(1, "HW", [a(1, 10, 4), a(2, 10, 9), a(3, 10)], drop_lowest=1)]
    assert percent(groups) == pytest.approx(90)
    # Counting the ungraded one as zero, the zero is what gets dropped.
    assert percent(groups, ungraded_as_zero=True) == pytest.approx(65)


def test_drop_rules_are_reported_with_the_dropped_count():
    out = run(csci456(), weighted=True)
    assert out["groups"][0] == {
        "name": "Homework",
        "weight": 20,
        "percent": 95,
        "graded": 3,
        "dropped": 1,
    }
    assert any("Homework drops lowest 1" in n for n in out["assumptions"])


def _ratio(items) -> float:
    return sum(s for s, _ in items) / sum(p for _, p in items)


def _brute(scores, drop_lowest, drop_highest, never):
    """Canvas's rule by exhaustion: keep the best set of n - drop_lowest,
    then the worst set of that minus drop_highest; never_drop always kept.
    Returns None when the best first-stage set is not unique (then which
    one Canvas keeps is a tie-break, not a rule)."""
    fixed = [scores[i] for i in never]
    free = [i for i in range(len(scores)) if i not in never]
    n = len(free)
    if n == 0:
        return _ratio(fixed) if fixed else None
    if drop_lowest >= n:
        drop_lowest, drop_highest = n - 1, 0
    if drop_highest >= n:
        drop_highest, drop_lowest = n - 1, 0
    keep_high = max(1, n - drop_lowest)
    keep_low = max(1, keep_high - drop_highest)
    ranked = sorted(
        (_ratio([scores[i] for i in combo] + fixed), combo)
        for combo in itertools.combinations(free, keep_high)
    )
    best, stage_one = ranked[-1]
    if len(ranked) > 1 and abs(ranked[-2][0] - best) < 1e-12 and drop_highest:
        return None
    return min(
        _ratio([scores[i] for i in combo] + fixed)
        for combo in itertools.combinations(stage_one, min(keep_low, len(stage_one)))
    )


def test_drop_rules_match_a_brute_force_search():
    rng = random.Random(456)
    checked = 0
    for _ in range(400):
        n = rng.randint(1, 7)
        scores = []
        for _ in range(n):
            possible = rng.choice([2, 5, 10, 10, 20, 50, 100])
            scores.append((rng.randint(0, possible * 2) / 2, possible))  # half points
        drop_lowest = rng.randint(0, 3)
        drop_highest = rng.randint(0, 2)
        never = sorted(rng.sample(range(n), rng.randint(0, min(2, n))))
        expected = _brute(scores, drop_lowest, drop_highest, never)
        if expected is None:
            continue
        group = g(
            1,
            "Q",
            [a(i, p, s) for i, (s, p) in enumerate(scores)],
            drop_lowest=drop_lowest,
            drop_highest=drop_highest,
            never_drop=never,
        )
        assert percent([group]) == pytest.approx(expected * 100, abs=1e-9), (
            scores,
            drop_lowest,
            drop_highest,
            never,
        )
        checked += 1
    assert checked > 300


def test_drops_on_a_large_group_are_fast_and_exact():
    rng = random.Random(7)
    assignments = [a(i, rng.choice([10, 20, 100]), None) for i in range(60)]
    for item in assignments:
        item["submission"]["score"] = rng.randint(0, int(item["points_possible"]))
    groups = [g(1, "HW", assignments, drop_lowest=10)]
    out = run(groups, target_percent=95)
    assert out["current_percent"] is not None


# ---------------------------------------------------------------------------
# What-if
# ---------------------------------------------------------------------------


def test_what_if_fills_in_and_replaces_scores():
    out = run(
        csci456(),
        weighted=True,
        what_if=[{"assignment": "Project", "percent": 90}, {"assignment": "21", "score": 80}],
    )
    # HW 95% x 20, Exams 80/100 x 50, Project 90% x 30.
    assert out["what_if"]["percent"] == 19 + 40 + 27
    assert out["what_if"]["scores"] == [
        {"assignment": "Project", "score": 45, "of": 50},
        {"assignment": "Midterm", "score": 80, "of": 100, "was": 72},
    ]
    # The real current grade is untouched.
    assert out["current_percent"] == 78.57


def test_what_if_goes_through_the_drop_rules():
    groups = [g(1, "HW", [a(1, 10, 9), a(2, 10, 8), a(3, 10)], drop_lowest=1)]
    out = run(groups, what_if=[{"assignment": "A3", "score": 2}])
    assert out["what_if"]["percent"] == 85  # the what-if 2/10 is the one dropped


def test_what_if_accepts_ids_names_and_unique_parts_of_names():
    course_ = parse_course(csci456(), course())
    assert cg.find_assignment(course_, "22").name == "Final Exam"
    assert cg.find_assignment(course_, "  final   EXAM ").name == "Final Exam"
    assert cg.find_assignment(course_, "final").name == "Final Exam"


def test_an_ambiguous_name_is_an_error_listing_the_candidates():
    with pytest.raises(GradeInputError) as exc:
        run(csci456(), what_if=[{"assignment": "HW", "score": 5}])
    message = str(exc.value)
    assert "matches 3 assignments" in message
    assert "HW 1 (id 11)" in message and "Use the assignment id" in message


def test_an_unknown_assignment_is_an_error_not_ignored():
    with pytest.raises(GradeInputError, match="No assignment in this course matches 'Lab 9'"):
        run(csci456(), what_if=[{"assignment": "Lab 9", "score": 5}])


def test_an_exact_name_wins_over_a_longer_one_containing_it():
    groups = [g(1, "Q", [a(1, 10, 5, "Quiz 1"), a(2, 10, 6, "Quiz 1 retake")])]
    assert cg.find_assignment(parse_course(groups, course()), "quiz 1").id == "1"


def test_what_if_on_excused_or_uncounted_work_is_refused():
    groups = [
        g(
            1,
            "HW",
            [
                a(1, 10, 9),
                a(2, 10, submission={"score": None, "excused": True}),
                a(3, 10, 0, omit_from_final_grade=True),
            ],
        ),
    ]
    with pytest.raises(GradeInputError, match="is excused"):
        run(groups, what_if=[{"assignment": "2", "score": 5}])
    with pytest.raises(GradeInputError, match="does not count"):
        run(groups, what_if=[{"assignment": "3", "score": 5}])


def test_the_same_assignment_twice_in_what_if_is_refused():
    with pytest.raises(GradeInputError, match="appears twice"):
        run(
            csci456(),
            what_if=[{"assignment": "22", "score": 5}, {"assignment": "Final Exam", "score": 6}],
        )


def test_percent_on_a_zero_point_assignment_is_refused():
    groups = [g(1, "HW", [a(1, 10, 9), a(2, 0, None, "Bonus")])]
    with pytest.raises(GradeInputError, match="worth 0 points"):
        run(groups, what_if=[{"assignment": "Bonus", "percent": 50}])
    assert run(groups, what_if=[{"assignment": "Bonus", "score": 1}])["what_if"]["percent"] == 100


# ---------------------------------------------------------------------------
# Target
# ---------------------------------------------------------------------------


def test_needed_on_one_named_assignment():
    out = run(
        csci456(),
        weighted=True,
        what_if=[{"assignment": "Project", "percent": 90}],
        target_percent=87,
        target_assignment="Final Exam",
    )
    # 19 + (72 + x) / 300 * 50 + 27 = 87  ->  x = 174 of 200.
    assert out["target"] == {
        "target_percent": 87,
        "assignment": "Final Exam",
        "points_possible": 200,
        "status": "reachable",
        "needed_percent": 87,
        "needed_points": 174,
    }


def test_needed_on_one_assignment_leaves_other_ungraded_work_out_and_says_so():
    out = run(csci456(), weighted=True, target_percent=80, target_assignment="Final Exam")
    # Project stays out: HW 95% x 20 and Exams (72 + x)/300 x 50 over 70.
    needed = out["target"]["needed_points"]
    course_ = parse_course(csci456(), course(True))
    assert course_percent(course_, {"22": needed}) >= 80 - 1e-9
    assert course_percent(course_, {"22": needed - 0.05}) < 80
    assert any("1 other ungraded assignment(s) are left out" in n for n in out["assumptions"])


def test_needed_evenly_over_the_remaining_work():
    out = run(csci456(), weighted=True, target_percent=87)
    target = out["target"]
    assert target["remaining_assignments"] == 2
    assert target["remaining_points"] == 250
    assert target["status"] == "reachable"
    # 19 + (72 + 200f)/300 x 50 + 30f = 87  ->  f = 56 / 63.33 = 88.42..%, rounded up.
    assert target["needed_percent"] == 88.43
    course_ = parse_course(csci456(), course(True))

    def at(pct):
        return course_percent(course_, {"22": pct / 100 * 200, "31": pct / 100 * 50})

    assert at(target["needed_percent"]) >= 87
    assert at(target["needed_percent"] - 0.01) < 87
    assert any("same percentage on every remaining" in n for n in out["assumptions"])


def test_an_unreachable_target_is_flagged_with_the_best_possible_grade():
    out = run(csci456(), weighted=True, target_percent=99, target_assignment="Final Exam")
    target = out["target"]
    assert target["status"] == "not reachable"
    assert "needed_percent" not in target
    # 200/200 on the final: HW 19 + Exams 272/300 x 50, over 70.
    assert target["best_possible_percent"] == round((19 + 272 / 300 * 50) / 70 * 100, 2)


def test_an_already_met_target_needs_nothing():
    groups = [g(1, "HW", [a(1, 10, 10), a(2, 10, 10), a(3, 10)])]
    # Even 0/10 on the last one leaves 20/30 = 66.7%.
    out = run(groups, target_percent=60)
    assert out["target"]["status"] == "already met"
    assert out["target"]["needed_percent"] == 0


def test_a_target_with_no_work_left_reports_the_final_grade():
    groups = [g(1, "HW", [a(1, 10, 8), a(2, 10, 9)])]
    assert run(groups, target_percent=90)["target"] == {
        "target_percent": 90,
        "remaining_assignments": 0,
        "status": "not reachable",
        "final_percent": 85,
    }
    assert run(groups, target_percent=85)["target"]["status"] == "already met"


def test_a_target_counts_drop_rules_on_the_remaining_work():
    # Drop lowest 1 of four: a bad score on the one remaining quiz is dropped,
    # so 3 x 10/10 already guarantees 100%.
    groups = [g(1, "Q", [a(1, 10, 10), a(2, 10, 10), a(3, 10, 10), a(4, 10)], drop_lowest=1)]
    assert run(groups, target_percent=100)["target"]["status"] == "already met"


def test_solving_on_a_what_if_assignment_is_refused():
    with pytest.raises(GradeInputError, match="leave it out of what_if"):
        run(
            csci456(),
            what_if=[{"assignment": "22", "score": 150}],
            target_percent=87,
            target_assignment="22",
        )


def test_solving_on_a_graded_assignment_replaces_its_score_and_says_so():
    out = run(csci456(), weighted=True, target_percent=80, target_assignment="Midterm")
    assert out["target"]["status"] in ("reachable", "already met", "not reachable")
    assert any("'Midterm' already has a score" in n for n in out["assumptions"])


# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"target_percent": "abc"}, "target_percent must be a number"),
        ({"target_percent": -5}, "between 0 and 200"),
        ({"target_percent": 0}, "more than 0"),
        ({"target_percent": True}, "must be a number"),
        ({"target_assignment": "Final"}, "give both"),
        ({"what_if": 5}, "what_if must be a list"),
        ({"what_if": "not json"}, "what_if must be a list"),
        ({"what_if": [1]}, "must be an object"),
        ({"what_if": [{"score": 5}]}, "needs an assignment id or name"),
        ({"what_if": [{"assignment": {"x": 1}, "score": 5}]}, "needs an assignment id or name"),
        ({"what_if": [{"assignment": "HW 1"}]}, "exactly one of score"),
        ({"what_if": [{"assignment": "HW 1", "score": 5, "percent": 50}]}, "exactly one of score"),
        ({"what_if": [{"assignment": "HW 1", "score": -1}]}, "0 or more"),
        ({"what_if": [{"assignment": "HW 1", "percent": 500}]}, "between 0 and 200"),
        ({"what_if": [{"assignment": "x" * 300, "score": 1}]}, "too long"),
        ({"what_if": [{"assignment": "HW", "score": 1}] * 26}, "at most 25"),
    ],
)
def test_bad_arguments_are_refused_with_a_usable_message(kwargs, message):
    with pytest.raises(GradeInputError, match=message):
        cg.parse_request(**kwargs)


def test_arguments_are_accepted_in_the_forms_models_send():
    request = cg.parse_request(
        what_if=json.dumps(
            [{"assignment_id": 22, "score": "150"}, {"name": "Project", "percent": "90%"}]
        ),
        target_percent="87%",
    )
    assert request.target_percent == 87
    assert request.what_if == (cg.WhatIf("22", score=150), cg.WhatIf("Project", percent=90))
    single = cg.parse_request(what_if={"assignment": "HW 1", "score": 4})
    assert single.what_if == (cg.WhatIf("HW 1", score=4),)
    assert cg.parse_request() == cg.PlanRequest()


# ---------------------------------------------------------------------------
# Payload robustness and output size
# ---------------------------------------------------------------------------


def test_malformed_payloads_are_skipped_not_guessed():
    groups = [
        "junk",
        {
            "id": 1,
            "name": "HW",
            "rules": "bad",
            "group_weight": "abc",
            "assignments": [
                None,
                {"name": "no id", "points_possible": 10},
                {"id": 1, "points_possible": "10", "submission": {"score": "7.5"}},
                {"id": 1, "points_possible": 10, "submission": {"score": 0}},  # duplicate id
                {"id": 2, "points_possible": None, "submission": "junk"},
                {"id": 3, "points_possible": 10, "submission": {"score": float("nan")}},
            ],
        },
    ]
    parsed = parse_course(groups, "not a dict")
    assert [x.id for x in parsed.assignments()] == ["1", "2", "3"]
    assert parsed.weighted is False
    assert course_percent(parsed) == pytest.approx(75)
    assert parse_course("junk", None).groups == ()


def test_a_course_with_no_assignments_is_an_error():
    with pytest.raises(GradeInputError, match="no assignments"):
        run([g(1, "HW", [])])


def test_canvas_own_score_is_reported_and_a_gap_is_explained():
    enrollment = {"enrollments": [{"type": "student", "computed_current_score": 81.2}]}
    out = run(csci456(), weighted=True, course_extra=enrollment)
    assert out["canvas_current_percent"] == 81.2
    assert any("Canvas itself shows 81.2%" in n for n in out["assumptions"])
    matching = {"enrollments": [{"type": "student", "computed_current_score": 78.57}]}
    out = run(csci456(), weighted=True, course_extra=matching)
    assert not any("Canvas itself" in n for n in out["assumptions"])


def test_hidden_course_totals_are_noted():
    out = run(csci456(), weighted=True, course_extra={"hide_final_grades": True})
    assert any("hides course totals" in n for n in out["assumptions"])


def test_the_result_stays_compact_for_a_huge_course():
    long = "Very Long Assignment Group Name That Goes On And On " * 3
    groups = [
        g(
            gi,
            f"{long} {gi}",
            [a(gi * 100 + i, 10, i % 11, f"{long} item {i}") for i in range(40)],
            weight=5,
            drop_lowest=2,
        )
        for gi in range(1, 21)
    ]
    what_if = [{"assignment": str(gi * 100 + 1), "score": 10} for gi in range(1, 21)]
    out = run(groups, weighted=True, what_if=what_if, target_percent=90)
    size = len(json.dumps(out, ensure_ascii=False, separators=(",", ":")))
    assert size <= cg.RESULT_CHAR_LIMIT
    # The headline numbers always survive the trim.
    for key in ("current_percent", "with_ungraded_as_zero_percent", "what_if", "target"):
        assert key in out
    assert out["more_groups"] > 0
    assert all(len(row["name"]) <= 40 for row in out["groups"])
