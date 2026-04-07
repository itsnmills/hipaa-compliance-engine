"""Workforce Security — training, access termination, authorization."""

from __future__ import annotations

from datetime import datetime

from engine.models import CheckResult, CheckStatus, Finding
from checks.base import BaseCheck


class WorkforceSecurityCheck(BaseCheck):
    """Verify workforce training, termination procedures, and authorization."""

    def execute(self, control_id: str, method: str) -> CheckResult:
        if self.demo:
            return self._demo_check(control_id, method)
        return self._live_check(control_id, method)

    def _live_check(self, control_id: str, method: str) -> CheckResult:
        """Live mode: load evidence from user-configured file path."""
        data = self._load_evidence_file("workforce_roster")
        if data is None:
            return self._make_not_configured_result(control_id, "workforce_roster", 365)
        dispatch = {
            "check_training_compliance": self._check_training_compliance,
            "check_access_termination": self._check_access_termination,
            "check_workforce_authorization": self._check_workforce_authorization,
        }
        handler = dispatch.get(method, self._check_training_compliance)
        return handler(control_id, data)


    def _demo_check(self, control_id: str, method: str) -> CheckResult:
        data = self._load_demo_data("workforce_roster.json") or {}
        dispatch = {
            "check_training_compliance": self._check_training_compliance,
            "check_access_termination": self._check_access_termination,
            "check_workforce_authorization": self._check_workforce_authorization,
        }
        handler = dispatch.get(method, self._check_training_compliance)
        return handler(control_id, data)

    def _check_training_compliance(self, control_id: str, data: dict) -> CheckResult:
        """Check security awareness training completion."""
        members = data.get("workforce_members", [])

        findings = []
        score = 1.0

        # Check training completion
        expired_training = [
            m for m in members
            if m.get("training_status") == "expired"
        ]
        never_trained = [
            m for m in members
            if m.get("training_status") == "never_completed"
        ]

        total = len(members)
        compliant = total - len(expired_training) - len(never_trained)
        compliance_rate = compliant / total if total > 0 else 0

        if expired_training:
            score -= 0.1 * len(expired_training) / max(total, 1)
            names = [m.get("name", "?") for m in expired_training[:5]]
            findings.append(Finding(
                control_id=control_id,
                title=f"{len(expired_training)} Staff With Expired Training",
                description=f"Security awareness training has expired for: {', '.join(names)}"
                          + (f" and {len(expired_training) - 5} more" if len(expired_training) > 5 else ""),
                severity="Medium",
                cfr_reference="45 CFR § 164.308(a)(5)",
                remediation="Schedule training renewal for all staff with expired certification. "
                          "Training must be completed annually.",
                evidence_summary=f"Expired: {names}",
                estimated_effort="Quick Win",
            ))

        if never_trained:
            score -= 0.15 * len(never_trained) / max(total, 1)
            names = [m.get("name", "?") for m in never_trained[:5]]
            findings.append(Finding(
                control_id=control_id,
                title=f"{len(never_trained)} Staff Never Completed Training",
                description=f"Staff members who have never completed HIPAA training: {', '.join(names)}",
                severity="High",
                cfr_reference="45 CFR § 164.308(a)(5)",
                remediation="Enroll untrained staff in HIPAA security awareness training immediately.",
                evidence_summary=f"Never trained: {names}",
                estimated_effort="Quick Win",
            ))

        score = max(0.0, score)
        if not findings:
            status = CheckStatus.PASS.value
        elif compliance_rate < 0.8:
            status = CheckStatus.FAIL.value
        else:
            status = CheckStatus.PARTIAL.value

        evidence = {
            "total_workforce": total,
            "training_compliant": compliant,
            "training_expired": len(expired_training),
            "never_trained": len(never_trained),
            "compliance_rate": f"{compliance_rate:.0%}",
        }

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=evidence, findings=findings,
            details=f"Training: {compliant}/{total} compliant ({compliance_rate:.0%})",
            decay_days=365,
        )

    def _check_access_termination(self, control_id: str, data: dict) -> CheckResult:
        """Check 1-hour access termination procedures."""
        termination = data.get("termination_procedures", {})
        recent_terminations = data.get("recent_terminations", [])

        findings = []
        score = 1.0

        if not termination.get("documented", False):
            score -= 0.3
            findings.append(Finding(
                control_id=control_id,
                title="No Documented Termination Procedures",
                description="Access termination procedures are not formally documented.",
                severity="High",
                cfr_reference="45 CFR § 164.308(a)(3)(ii)(C)",
                remediation="Document access termination procedures with 1-hour SLA requirement.",
                estimated_effort="Short-term",
            ))

        sla_met = termination.get("sla_1hr_capable", False)
        if not sla_met:
            score -= 0.3
            findings.append(Finding(
                control_id=control_id,
                title="1-Hour Termination SLA Not Achievable",
                description="Current procedures cannot guarantee access termination within 1 hour.",
                severity="Critical",
                cfr_reference="45 CFR § 164.308(a)(3)(ii)(C)",
                remediation="Implement automated access termination workflow achieving "
                          "1-hour SLA. Consider integration with HR and identity provider systems.",
                estimated_effort="Strategic",
            ))

        # Check recent terminations for SLA compliance
        sla_violations = [
            t for t in recent_terminations
            if t.get("termination_time_minutes", 999) > 60
        ]
        if sla_violations:
            score -= 0.15
            findings.append(Finding(
                control_id=control_id,
                title=f"{len(sla_violations)} Termination SLA Violation(s)",
                description=f"Recent terminations exceeded 1-hour SLA.",
                severity="High",
                cfr_reference="45 CFR § 164.308(a)(3)(ii)(C)",
                remediation="Investigate SLA violations and improve termination procedures.",
                evidence_summary=f"Violations: {len(sla_violations)}",
                estimated_effort="Short-term",
            ))

        score = max(0.0, score)
        if not findings:
            status = CheckStatus.PASS.value
        elif any(f.severity == "Critical" for f in findings):
            status = CheckStatus.FAIL.value
        else:
            status = CheckStatus.PARTIAL.value

        evidence = {
            "documented": termination.get("documented", False),
            "sla_1hr_capable": sla_met,
            "automated": termination.get("automated", False),
            "recent_terminations": len(recent_terminations),
            "sla_violations": len(sla_violations),
        }

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=evidence, findings=findings,
            details=f"Termination: documented={termination.get('documented', False)}, "
                   f"1hr SLA={sla_met}, violations={len(sla_violations)}",
            decay_days=180,
        )

    def _check_workforce_authorization(self, control_id: str, data: dict) -> CheckResult:
        """Check workforce authorization and supervision."""
        authorization = data.get("authorization", {})

        findings = []
        score = 1.0

        if not authorization.get("clearance_procedures", False):
            score -= 0.2
            findings.append(Finding(
                control_id=control_id,
                title="No Clearance Procedures Documented",
                description="Workforce clearance procedures are not documented.",
                severity="Medium",
                cfr_reference="45 CFR § 164.308(a)(3)",
                remediation="Document clearance procedures for workforce access to ePHI.",
                estimated_effort="Short-term",
            ))

        if not authorization.get("supervision_policy", False):
            score -= 0.15
            findings.append(Finding(
                control_id=control_id,
                title="No Supervision Policy",
                description="No formal supervision policy for workforce ePHI access.",
                severity="Medium",
                cfr_reference="45 CFR § 164.308(a)(3)",
                remediation="Implement workforce supervision policies for ePHI access.",
                estimated_effort="Short-term",
            ))

        score = max(0.0, score)
        if not findings:
            status = CheckStatus.PASS.value
        else:
            status = CheckStatus.PARTIAL.value

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=authorization, findings=findings,
            details=f"Workforce auth: clearance={authorization.get('clearance_procedures', False)}, "
                   f"supervision={authorization.get('supervision_policy', False)}",
            decay_days=180,
        )

    def get_evidence(self) -> dict:
        return self._evidence
