"""Access Control & RBAC verification check module."""

from __future__ import annotations

from engine.models import CheckResult, CheckStatus, Finding
from checks.base import BaseCheck


class AccessControlsCheck(BaseCheck):
    """Verify access controls, unique user IDs, and RBAC implementation."""

    def execute(self, control_id: str, method: str) -> CheckResult:
        if self.demo:
            return self._demo_check(control_id, method)
        return self._make_result(
            control_id=control_id,
            status=CheckStatus.ERROR.value,
            score=0.0,
            details="Live access control check requires directory service configuration",
        )

    def _demo_check(self, control_id: str, method: str) -> CheckResult:
        data = self._load_demo_data("mfa_config.json") or {}
        dispatch = {
            "check_unique_users": self._check_unique_users,
            "check_access_authorization": self._check_access_authorization,
        }
        handler = dispatch.get(method, self._check_unique_users)
        return handler(control_id, data)

    def _check_unique_users(self, control_id: str, data: dict) -> CheckResult:
        """Check for unique user IDs and no shared accounts."""
        users = data.get("users", [])
        shared_accounts = data.get("shared_accounts", [])
        rbac_configured = data.get("rbac_configured", False)

        findings = []
        score = 1.0

        if shared_accounts:
            score -= 0.2 * len(shared_accounts)
            findings.append(Finding(
                control_id=control_id,
                title=f"{len(shared_accounts)} Shared Account(s) Detected",
                description=f"Shared accounts violate unique user ID requirements: "
                          f"{', '.join(a.get('name', '?') for a in shared_accounts)}",
                severity="High",
                cfr_reference="45 CFR § 164.312(a)(1)",
                remediation="Eliminate all shared accounts. Create individual user accounts "
                          "for each workforce member with unique identifiers.",
                evidence_summary=f"Shared accounts: {[a.get('name') for a in shared_accounts]}",
                estimated_effort="Short-term",
            ))

        if not rbac_configured:
            score -= 0.2
            findings.append(Finding(
                control_id=control_id,
                title="RBAC Not Fully Implemented",
                description="Role-based access control is not fully configured across ePHI systems.",
                severity="Medium",
                cfr_reference="45 CFR § 164.312(a)(1)",
                remediation="Implement role-based access control with defined roles and "
                          "minimum necessary access permissions.",
                estimated_effort="Short-term",
            ))

        score = max(0.0, score)
        if not findings:
            status = CheckStatus.PASS.value
        elif shared_accounts:
            status = CheckStatus.FAIL.value
        else:
            status = CheckStatus.PARTIAL.value

        evidence = {
            "total_users": len(users),
            "shared_accounts": len(shared_accounts),
            "rbac_configured": rbac_configured,
            "auto_logoff_enabled": data.get("auto_logoff_enabled", False),
        }

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=evidence, findings=findings,
            details=f"Users: {len(users)}, Shared accounts: {len(shared_accounts)}, RBAC: {rbac_configured}",
            decay_days=180,
        )

    def _check_access_authorization(self, control_id: str, data: dict) -> CheckResult:
        """Check access authorization and review procedures."""
        access_reviews = data.get("access_reviews", [])
        authorization_policy = data.get("authorization_policy_exists", False)

        findings = []
        score = 1.0

        if not authorization_policy:
            score -= 0.3
            findings.append(Finding(
                control_id=control_id,
                title="No Access Authorization Policy",
                description="No formal access authorization policy found for ePHI systems.",
                severity="High",
                cfr_reference="45 CFR § 164.308(a)(4)",
                remediation="Develop and implement a formal access authorization policy "
                          "covering request, approval, and review processes.",
                estimated_effort="Short-term",
            ))

        if not access_reviews:
            score -= 0.2
            findings.append(Finding(
                control_id=control_id,
                title="No Access Reviews Conducted",
                description="No evidence of periodic access reviews for ePHI systems.",
                severity="Medium",
                cfr_reference="45 CFR § 164.308(a)(4)",
                remediation="Conduct access reviews at least semi-annually. Document "
                          "review findings and remediate inappropriate access.",
                estimated_effort="Short-term",
            ))

        score = max(0.0, score)
        if not findings:
            status = CheckStatus.PASS.value
        elif score < 0.5:
            status = CheckStatus.FAIL.value
        else:
            status = CheckStatus.PARTIAL.value

        evidence = {
            "authorization_policy": authorization_policy,
            "access_reviews_count": len(access_reviews),
        }

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=evidence, findings=findings,
            details=f"Authorization policy: {authorization_policy}, Reviews: {len(access_reviews)}",
            decay_days=180,
        )

    def get_evidence(self) -> dict:
        return self._evidence
