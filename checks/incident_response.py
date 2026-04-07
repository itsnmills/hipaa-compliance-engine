"""Incident Response Plan & Testing verification check module."""

from __future__ import annotations

from datetime import datetime

from engine.models import CheckResult, CheckStatus, Finding
from checks.base import BaseCheck


class IncidentResponseCheck(BaseCheck):
    """Verify IR plan existence, testing, and BA notification procedures."""

    def execute(self, control_id: str, method: str) -> CheckResult:
        if self.demo:
            return self._demo_check(control_id, method)
        return self._make_result(
            control_id=control_id,
            status=CheckStatus.ERROR.value,
            score=0.0,
            details="Live IR check requires evidence file configuration",
        )

    def _demo_check(self, control_id: str, method: str) -> CheckResult:
        data = self._load_demo_data("ir_plan.json") or {}
        return self._check_ir_plan(control_id, data)

    def _check_ir_plan(self, control_id: str, data: dict) -> CheckResult:
        """Check incident response plan and testing."""
        plan = data.get("plan", {})
        tests = data.get("tests", [])
        notification_procedures = data.get("notification_procedures", {})

        findings = []
        score = 1.0

        # Check plan exists
        if not plan.get("exists", False):
            return self._make_result(
                control_id=control_id,
                status=CheckStatus.FAIL.value,
                score=0.0,
                findings=[Finding(
                    control_id=control_id,
                    title="No Incident Response Plan",
                    description="No written incident response plan found.",
                    severity="Critical",
                    cfr_reference="45 CFR § 164.308(a)(6)",
                    remediation="Develop a comprehensive incident response plan covering "
                              "identification, containment, eradication, recovery, and lessons learned.",
                    estimated_effort="Short-term",
                )],
                details="No IR plan found",
                decay_days=365,
            )

        # Check plan review date
        last_review = plan.get("last_review", "")
        try:
            review_dt = datetime.fromisoformat(last_review)
            days_since_review = (datetime.now() - review_dt).days
        except (ValueError, TypeError):
            days_since_review = 999

        if days_since_review > 365:
            score -= 0.15
            findings.append(Finding(
                control_id=control_id,
                title="IR Plan Not Reviewed Within 12 Months",
                description=f"IR plan last reviewed {days_since_review} days ago.",
                severity="Medium",
                cfr_reference="45 CFR § 164.308(a)(6)",
                remediation="Review and update the incident response plan at least annually.",
                estimated_effort="Quick Win",
            ))

        # Check testing
        if not tests:
            score -= 0.25
            findings.append(Finding(
                control_id=control_id,
                title="No IR Plan Testing",
                description="No tabletop exercises or IR plan tests have been conducted.",
                severity="High",
                cfr_reference="45 CFR § 164.308(a)(6)",
                remediation="Conduct a tabletop exercise or IR simulation at least annually.",
                estimated_effort="Short-term",
            ))
        else:
            latest_test = tests[0]
            test_date = latest_test.get("date", "")
            try:
                test_dt = datetime.fromisoformat(test_date)
                days_since_test = (datetime.now() - test_dt).days
            except (ValueError, TypeError):
                days_since_test = 999

            if days_since_test > 365:
                score -= 0.15
                findings.append(Finding(
                    control_id=control_id,
                    title="IR Plan Testing Overdue",
                    description=f"Last IR test was {days_since_test} days ago.",
                    severity="Medium",
                    cfr_reference="45 CFR § 164.308(a)(6)",
                    remediation="Schedule an IR tabletop exercise within 30 days.",
                    estimated_effort="Quick Win",
                ))

        # Check 24-hour notification procedures
        if not notification_procedures.get("ba_24hr_notification", False):
            score -= 0.1
            findings.append(Finding(
                control_id=control_id,
                title="No 24-Hour BA Notification Procedure",
                description="IR plan does not include 24-hour BA notification procedures.",
                severity="Medium",
                cfr_reference="45 CFR § 164.308(b)(3)",
                remediation="Add 24-hour BA contingency notification procedures to IR plan.",
                estimated_effort="Quick Win",
            ))

        score = max(0.0, score)
        if not findings:
            status = CheckStatus.PASS.value
        elif score <= 0.5:
            status = CheckStatus.FAIL.value
        else:
            status = CheckStatus.PARTIAL.value

        evidence = {
            "plan_exists": plan.get("exists", False),
            "last_review": last_review,
            "tests_conducted": len(tests),
            "ba_notification": notification_procedures.get("ba_24hr_notification", False),
            "plan_version": plan.get("version", "Unknown"),
        }

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=evidence, findings=findings,
            details=f"IR plan: {'exists' if plan.get('exists') else 'missing'}, Tests: {len(tests)}",
            decay_days=365,
        )

    def get_evidence(self) -> dict:
        return self._evidence
