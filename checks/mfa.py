"""MFA Enforcement Verification check module."""

from __future__ import annotations

from engine.models import CheckResult, CheckStatus, Finding
from checks.base import BaseCheck


class MFACheck(BaseCheck):
    """Verify MFA is configured and enforced across identity providers."""

    def execute(self, control_id: str, method: str) -> CheckResult:
        """Run MFA verification check."""
        if self.demo:
            return self._demo_check(control_id, method)

        # Live mode: would check Azure AD, Google Workspace, Okta APIs
        return self._make_result(
            control_id=control_id,
            status=CheckStatus.ERROR.value,
            score=0.0,
            details="Live MFA check requires identity provider API configuration",
        )

    def _demo_check(self, control_id: str, method: str) -> CheckResult:
        """Demo mode MFA check for Midwest Family Dental."""
        data = self._load_demo_data("mfa_config.json") or {}

        if method == "check_mfa_enforcement":
            return self._check_mfa_enforcement(control_id, data)
        elif method == "check_universal_mfa":
            return self._check_universal_mfa(control_id, data)
        else:
            return self._check_mfa_enforcement(control_id, data)

    def _check_mfa_enforcement(self, control_id: str, data: dict) -> CheckResult:
        """Check MFA enforcement across identity providers."""
        providers = data.get("identity_providers", [])
        total_users = data.get("total_users", 0)
        mfa_enrolled = data.get("mfa_enrolled", 0)
        enrollment_rate = mfa_enrolled / total_users if total_users > 0 else 0

        findings = []
        exceptions = data.get("mfa_exceptions", [])
        if exceptions:
            findings.append(Finding(
                control_id=control_id,
                title="MFA Exceptions Detected",
                description=f"{len(exceptions)} user(s) have MFA exceptions: "
                           f"{', '.join(e.get('user', 'unknown') for e in exceptions)}",
                severity="High",
                cfr_reference="45 CFR § 164.312(d)",
                remediation="Remove all MFA exceptions. Under the 2025 HIPAA Security Rule, "
                          "MFA is mandatory for ALL users accessing ePHI with no exceptions.",
                evidence_summary=f"Exception list: {exceptions}",
                estimated_effort="Quick Win",
            ))

        if enrollment_rate >= 1.0:
            status = CheckStatus.PASS.value
            score = 1.0
        elif enrollment_rate >= 0.9:
            status = CheckStatus.PARTIAL.value
            score = 0.85
        else:
            status = CheckStatus.FAIL.value
            score = enrollment_rate * 0.7

        evidence = {
            "providers_checked": len(providers),
            "total_users": total_users,
            "mfa_enrolled": mfa_enrolled,
            "enrollment_rate": f"{enrollment_rate:.1%}",
            "exceptions": len(exceptions),
            "providers": [p.get("type", "unknown") for p in providers],
        }

        return self._make_result(
            control_id=control_id,
            status=status,
            score=score,
            evidence=evidence,
            findings=findings,
            details=f"MFA enrollment: {mfa_enrolled}/{total_users} ({enrollment_rate:.0%})",
            decay_days=30,
        )

    def _check_universal_mfa(self, control_id: str, data: dict) -> CheckResult:
        """Check if MFA is universally enforced (no exceptions)."""
        total_users = data.get("total_users", 0)
        mfa_enrolled = data.get("mfa_enrolled", 0)
        exceptions = data.get("mfa_exceptions", [])
        conditional_access = data.get("conditional_access_policies", [])

        findings = []
        score = 1.0

        if exceptions:
            score -= 0.15 * len(exceptions)
            findings.append(Finding(
                control_id=control_id,
                title="MFA Not Universal — Exceptions Exist",
                description=f"{len(exceptions)} users exempt from MFA requirement. "
                          f"2025 rule mandates MFA for ALL ePHI access without exception.",
                severity="Critical",
                cfr_reference="45 CFR § 164.312(d)(2)",
                remediation="Immediately enroll all excepted users in MFA. Remove all "
                          "exception policies. The 2025 HIPAA rule eliminates the "
                          "addressable designation — MFA is now mandatory.",
                evidence_summary=f"Exceptions: {[e.get('user') for e in exceptions]}",
                estimated_effort="Quick Win",
            ))

        # Check conditional access policies exist
        has_require_mfa = any(
            p.get("requires_mfa", False) for p in conditional_access
        )
        if not has_require_mfa:
            score -= 0.2
            findings.append(Finding(
                control_id=control_id,
                title="No Conditional Access Policy Requiring MFA",
                description="No conditional access policy found that enforces MFA for "
                          "ePHI system access.",
                severity="High",
                cfr_reference="45 CFR § 164.312(d)(2)",
                remediation="Configure conditional access policies requiring MFA for all "
                          "applications and services accessing ePHI.",
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
            "total_users": total_users,
            "mfa_enrolled": mfa_enrolled,
            "exceptions_count": len(exceptions),
            "conditional_access_policies": len(conditional_access),
            "universal_enforcement": len(exceptions) == 0,
        }

        return self._make_result(
            control_id=control_id,
            status=status,
            score=score,
            evidence=evidence,
            findings=findings,
            details=f"MFA universal enforcement: {'Yes' if not exceptions else 'No — ' + str(len(exceptions)) + ' exceptions'}",
            decay_days=30,
        )

    def get_evidence(self) -> dict:
        return self._evidence
