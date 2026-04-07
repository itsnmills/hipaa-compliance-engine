"""Compliance freshness scoring with time-decay model."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from engine.models import (
    CheckResult, ControlDefinition, ControlStatus,
    CategoryScore, ComplianceReport, CheckStatus,
    get_score_band, Finding,
)


# Category weights for overall score calculation
DEFAULT_CATEGORY_WEIGHTS = {
    "Technical": 0.35,
    "Administrative": 0.30,
    "Cross-Cutting": 0.25,
    "Physical": 0.10,
}

# Warning threshold: alert when this fraction through decay period
FRESHNESS_WARNING_THRESHOLD = 0.25  # 75% through = 25% remaining


def calculate_freshness(
    check_timestamp: str,
    decay_days: int,
    current_time: Optional[datetime] = None,
) -> float:
    """Calculate freshness score for a check result.

    Formula: freshness = max(0, 1.0 - (days_since_check / decay_period))

    Args:
        check_timestamp: ISO format timestamp of when check was run.
        decay_days: Number of days until check goes stale.
        current_time: Override current time (for testing).

    Returns:
        Freshness score between 0.0 and 1.0.
    """
    if not check_timestamp:
        return 0.0

    now = current_time or datetime.now()

    try:
        check_time = datetime.fromisoformat(check_timestamp.replace("Z", "+00:00"))
        if check_time.tzinfo:
            check_time = check_time.replace(tzinfo=None)
    except (ValueError, AttributeError):
        return 0.0

    days_elapsed = (now - check_time).total_seconds() / 86400
    if days_elapsed < 0:
        return 1.0

    freshness = max(0.0, 1.0 - (days_elapsed / decay_days))
    return round(freshness, 4)


def calculate_effective_score(check_score: float, freshness: float) -> float:
    """Calculate the effective score factoring in freshness decay.

    Args:
        check_score: Raw check result score (0.0 to 1.0).
        freshness: Freshness multiplier (0.0 to 1.0).

    Returns:
        Effective score between 0.0 and 1.0.
    """
    return round(check_score * freshness, 4)


def compute_control_status(
    control: ControlDefinition,
    check_result: Optional[CheckResult],
    current_time: Optional[datetime] = None,
) -> ControlStatus:
    """Compute the full status of a control including freshness.

    Args:
        control: The control definition.
        check_result: Most recent check result, or None if never checked.
        current_time: Override current time (for testing).

    Returns:
        ControlStatus with freshness and effective score.
    """
    now = current_time or datetime.now()

    if check_result is None:
        return ControlStatus(
            control=control,
            last_check=None,
            freshness=0.0,
            effective_score=0.0,
            is_stale=True,
            days_since_check=None,
            next_due=now.isoformat(),
        )

    freshness = calculate_freshness(
        check_result.timestamp, control.freshness_decay_days, now
    )
    effective_score = calculate_effective_score(check_result.score, freshness)

    try:
        check_time = datetime.fromisoformat(
            check_result.timestamp.replace("Z", "+00:00")
        )
        if check_time.tzinfo:
            check_time = check_time.replace(tzinfo=None)
        days_since = int((now - check_time).total_seconds() / 86400)
        next_due_dt = check_time + timedelta(days=control.freshness_decay_days)
        next_due = next_due_dt.isoformat()
    except (ValueError, AttributeError):
        days_since = None
        next_due = None

    is_stale = freshness <= 0.0

    return ControlStatus(
        control=control,
        last_check=check_result,
        freshness=freshness,
        effective_score=effective_score,
        is_stale=is_stale,
        days_since_check=days_since,
        next_due=next_due,
    )


def is_approaching_stale(
    control_status: ControlStatus,
    warning_threshold: float = FRESHNESS_WARNING_THRESHOLD,
) -> bool:
    """Check if a control's check is approaching staleness.

    Args:
        control_status: Current control status.
        warning_threshold: Fraction of freshness remaining to trigger warning.

    Returns:
        True if the control is approaching staleness.
    """
    if control_status.is_stale:
        return False
    return control_status.freshness <= warning_threshold


def compute_category_score(
    control_statuses: list[ControlStatus],
    category: str,
) -> CategoryScore:
    """Compute the compliance score for a category.

    Args:
        control_statuses: All control statuses.
        category: Category name to compute score for.

    Returns:
        CategoryScore with breakdown.
    """
    cat_statuses = [cs for cs in control_statuses if cs.control.category == category]

    if not cat_statuses:
        return CategoryScore(
            category=category,
            score=0.0,
            weight=DEFAULT_CATEGORY_WEIGHTS.get(category, 0.0),
            weighted_score=0.0,
            controls_total=0,
            controls_passing=0,
            controls_failing=0,
            controls_partial=0,
        )

    total = len(cat_statuses)
    passing = sum(1 for cs in cat_statuses
                  if cs.last_check and cs.last_check.status == CheckStatus.PASS.value)
    failing = sum(1 for cs in cat_statuses
                  if cs.last_check and cs.last_check.status == CheckStatus.FAIL.value)
    partial = sum(1 for cs in cat_statuses
                  if cs.last_check and cs.last_check.status == CheckStatus.PARTIAL.value)

    # Score is average of effective scores * 100
    effective_scores = [cs.effective_score for cs in cat_statuses]
    score = (sum(effective_scores) / len(effective_scores)) * 100

    weight = DEFAULT_CATEGORY_WEIGHTS.get(category, 0.0)
    weighted_score = score * weight

    return CategoryScore(
        category=category,
        score=round(score, 1),
        weight=weight,
        weighted_score=round(weighted_score, 1),
        controls_total=total,
        controls_passing=passing,
        controls_failing=failing,
        controls_partial=partial,
    )


def compute_overall_score(
    category_scores: list[CategoryScore],
) -> float:
    """Compute the weighted overall compliance score.

    Args:
        category_scores: Scores for each category.

    Returns:
        Overall compliance score (0-100).
    """
    total_weight = sum(cs.weight for cs in category_scores)
    if total_weight == 0:
        return 0.0

    weighted_sum = sum(cs.score * cs.weight for cs in category_scores)
    return round(weighted_sum / total_weight, 1)


def build_compliance_report(
    organization_name: str,
    organization_type: str,
    control_statuses: list[ControlStatus],
    history: list[dict] | None = None,
) -> ComplianceReport:
    """Build a complete compliance report from control statuses.

    Args:
        organization_name: Name of the organization.
        organization_type: Type (covered_entity, business_associate).
        control_statuses: All computed control statuses.
        history: Historical check run data.

    Returns:
        ComplianceReport with all computed data.
    """
    # Compute category scores
    categories = sorted(set(cs.control.category for cs in control_statuses))
    category_scores = [
        compute_category_score(control_statuses, cat) for cat in categories
    ]

    overall_score = compute_overall_score(category_scores)
    overall_band = get_score_band(overall_score).value

    # Collect all findings
    all_findings: list[Finding] = []
    all_results: list[CheckResult] = []
    for cs in control_statuses:
        if cs.last_check:
            all_results.append(cs.last_check)
            all_findings.extend(cs.last_check.findings)

    # Sort findings by severity
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    all_findings.sort(key=lambda f: severity_order.get(f.severity, 99))

    # Identify stale and approaching-stale controls
    stale = [cs for cs in control_statuses if cs.is_stale]
    approaching = [cs for cs in control_statuses if is_approaching_stale(cs)]

    return ComplianceReport(
        organization_name=organization_name,
        organization_type=organization_type,
        report_date=datetime.now().strftime("%Y-%m-%d"),
        overall_score=overall_score,
        overall_band=overall_band,
        category_scores=category_scores,
        control_statuses=control_statuses,
        findings=all_findings,
        check_results=all_results,
        stale_controls=stale,
        approaching_stale=approaching,
        history=history or [],
    )
