"""
A deliberately simple, deterministic, heuristic 0-100 security score --
not an authoritative compliance measure, just a quick signal that
combines the other analysis checks with capped per-category deductions
so no single category can single-handedly zero out the score.
"""
from __future__ import annotations

from typing import Any


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def score_security(
    *,
    any_any_count: int,
    shadowed_count: int,
    duplicate_count: int,
    unused_count: int,
    best_practice_issues: list[dict[str, Any]],
    system_config_issues: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    score = 100
    deductions = []

    def _deduct(count: int, per_item: int, cap: int, reason: str) -> None:
        nonlocal score
        if count <= 0:
            return
        points = min(count * per_item, cap)
        score -= points
        deductions.append({"reason": reason, "points": points})

    _deduct(any_any_count, 15, 40, f"{any_any_count} any-any-any polic{'y' if any_any_count == 1 else 'ies'}")
    _deduct(shadowed_count, 5, 20, f"{shadowed_count} shadowed polic{'y' if shadowed_count == 1 else 'ies'}")
    _deduct(duplicate_count, 3, 15, f"{duplicate_count} duplicate policy group(s)")
    _deduct(unused_count, 1, 10, f"{unused_count} unused object(s)")

    high = sum(1 for i in best_practice_issues if i.get("severity") == "high")
    medium = sum(1 for i in best_practice_issues if i.get("severity") == "medium")
    low = sum(1 for i in best_practice_issues if i.get("severity") == "low")
    bp_points = min(high * 5 + medium * 2 + low * 1, 15)
    if bp_points:
        score -= bp_points
        deductions.append(
            {"reason": f"{high} high / {medium} medium / {low} low best-practice issues", "points": bp_points}
        )

    if system_config_issues:
        sc_high = sum(1 for i in system_config_issues if i.get("severity") == "high")
        sc_medium = sum(1 for i in system_config_issues if i.get("severity") == "medium")
        sc_low = sum(1 for i in system_config_issues if i.get("severity") == "low")
        sc_points = min(sc_high * 5 + sc_medium * 2 + sc_low * 1, 15)
        if sc_points:
            score -= sc_points
            deductions.append(
                {
                    "reason": f"{sc_high} high / {sc_medium} medium / {sc_low} low system-config issues",
                    "points": sc_points,
                }
            )

    score = max(0, score)
    return {"score": score, "grade": _grade(score), "deductions": deductions}
