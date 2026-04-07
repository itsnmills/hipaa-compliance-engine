"""Penetration Testing evidence verification check module."""

from __future__ import annotations

from datetime import datetime

from engine.models import CheckResult, CheckStatus, Finding
from checks.base import BaseCheck


class PenetrationTestingCheck(BaseCheck):
    """Verify annual penetration testing has been conducted."""

    def execute(self, control_id: str, method: str) -> CheckResult:
        if self.demo:
            return self._demo_check(control_id, method)
        return self._make_result(
            control_id=control_id,
            status=CheckStatus.ERROR.value,
            score=0.0,
            details="Live pen test check requires evidence file configuration",
        )

    def _demo_check(self, control_id: str, method: str) -> CheckResult:
        data = self._load_demo_data("pentest_report.json") or {}
        return self._check_pentest_compliance(control_id, data)

    def _check_pentest_compliance(self, control_id: str, data: dict) -> CheckResult:
        """Check penetration test compliance."""
        report = data.get("report", {})
        test_date = report.get("test_date", "")
        findings_list = data.get("findings", [])

        findings = []
        score = 1.0

        # Check test date
        try:
            test_dt = datetime.fromisoformat(test_date)
            days_since = (datetime.now() - test_dt).days
        except (ValueError, TypeError):
            days_since = 999

        if days_since > 365:
            score -= 0.5
            findings.append(Finding(
                control_id=control_id,
                title="Penetration Test Overdue",
                description=f"Last penetration test was {days_since} days ago. "
                          f"Annual testing is required.",
                severity="High",
                cfr_reference="45 CFR § 164.308(a)(8)",
                remediation="Schedule a penetration test immediately with a qualified tester.",
                evidence_summary=f"Last test: {test_date}, Days since: {days_since}",
                estimated_effort="Short-term",
            ))

        # Check tester qualifications
        tester = report.get("tester", {})
        if not tester.get("qualified", False):
            score -= 0.15
            findings.append(Finding(
                control_id=control_id,
                title="Tester Qualifications Not Verified",
                description="Penetration tester qualifications could not be verified.",
                severity="Medium",
                cfr_reference="45 CFR § 164.308(a)(8)",
                remediation="Ensure pen test is conducted by a qualified professional "
                          "(e.g., OSCP, CEH, GPEN certified).",
                estimated_effort="Short-term",
            ))

        # Check unremediated findings
        open_findings = [f for f in findings_list if f.get("status") != "remediated"]
        critical_open = [f for f in open_findings if f.get("severity") == "Critical"]

        if critical_open:
            score -= 0.2
            findings.append(Finding(
                control_id=control_id,
                title=f"{len(critical_open)} Critical Pen Test Findings Unremediated",
                description=f"Critical findings from pen test remain open: "
                          f"{', '.join(f.get('title', 'N/A') for f in critical_open[:3])}",
                severity="Critical",
                cfr_reference="45 CFR § 164.308(a)(8)",
                remediation="Remediate all critical penetration test findings immediately.",
                evidence_summary=f"Open critical: {[f.get('title') for f in critical_open]}",
                estimated_effort="Short-term",
            ))

        score = max(0.0, score)

        if not findings:
            status = CheckStatus.PASS.value
        elif days_since > 365 or critical_open:
            status = CheckStatus.FAIL.value
        else:
            status = CheckStatus.PARTIAL.value

        evidence = {
            "last_test_date": test_date,
            "days_since_test": days_since,
            "tester_name": tester.get("name", "Unknown"),
            "tester_company": tester.get("company", "Unknown"),
            "total_findings": len(findings_list),
            "remediated": len([f for f in findings_list if f.get("status") == "remediated"]),
            "open": len(open_findings),
        }

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=evidence, findings=findings,
            details=f"Pen test: {days_since}d ago, {len(open_findings)} open findings",
            decay_days=365,
        )

    def get_evidence(self) -> dict:
        return self._evidence
