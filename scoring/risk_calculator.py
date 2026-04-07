"""Risk scoring and calculation utilities."""

from __future__ import annotations

from engine.models import (
    ComplianceReport, ControlStatus, Finding, Severity,
    get_score_band, ScoreBand,
)


def calculate_risk_score(likelihood: int, impact: int, weight: float = 1.0) -> float:
    """Calculate risk score for a finding.

    Args:
        likelihood: Likelihood of exploitation (1-5).
        impact: Impact if exploited (1-5).
        weight: Control severity weight multiplier.

    Returns:
        Risk score (0-75 max range).
    """
    return likelihood * impact * weight


def get_severity_for_score(effective_score: float) -> str:
    """Determine severity based on effective compliance score.

    Args:
        effective_score: Score between 0.0 and 1.0.

    Returns:
        Severity level string.
    """
    if effective_score >= 0.9:
        return Severity.LOW.value
    elif effective_score >= 0.7:
        return Severity.MEDIUM.value
    elif effective_score >= 0.4:
        return Severity.HIGH.value
    else:
        return Severity.CRITICAL.value


def prioritize_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings by priority for remediation.

    Sorts by severity (Critical first), then by effort (Quick Wins first
    within same severity).

    Args:
        findings: List of findings to prioritize.

    Returns:
        Sorted findings list.
    """
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    effort_order = {"Quick Win": 0, "Short-term": 1, "Strategic": 2}

    return sorted(
        findings,
        key=lambda f: (
            severity_order.get(f.severity, 99),
            effort_order.get(f.estimated_effort, 99),
        ),
    )


def get_next_actions(
    report: ComplianceReport,
    max_actions: int = 5,
) -> list[dict]:
    """Get prioritized next actions from report findings.

    Args:
        report: Complete compliance report.
        max_actions: Maximum number of actions to return.

    Returns:
        List of action dictionaries with control info and recommendations.
    """
    actions = []

    # Priority 1: Stale critical controls
    for cs in report.stale_controls:
        if cs.control.severity == Severity.CRITICAL.value:
            actions.append({
                "priority": "URGENT",
                "control_id": cs.control.id,
                "title": cs.control.title,
                "action": f"Re-run stale check (last run: {cs.days_since_check or '?'} days ago)",
                "category": cs.control.category,
            })

    # Priority 2: Failed critical controls
    for cs in report.failing_controls:
        if cs.control.severity == Severity.CRITICAL.value:
            actions.append({
                "priority": "CRITICAL",
                "control_id": cs.control.id,
                "title": cs.control.title,
                "action": cs.control.remediation_guidance[:120] + "...",
                "category": cs.control.category,
            })

    # Priority 3: Failed high controls
    for cs in report.failing_controls:
        if cs.control.severity == Severity.HIGH.value:
            actions.append({
                "priority": "HIGH",
                "control_id": cs.control.id,
                "title": cs.control.title,
                "action": cs.control.remediation_guidance[:120] + "...",
                "category": cs.control.category,
            })

    # Priority 4: Approaching stale controls
    for cs in report.approaching_stale:
        actions.append({
            "priority": "WARNING",
            "control_id": cs.control.id,
            "title": cs.control.title,
            "action": f"Check approaching staleness (freshness: {cs.freshness:.0%})",
            "category": cs.control.category,
        })

    return actions[:max_actions]
