"""Technology Asset Inventory & Network Map verification check module."""

from __future__ import annotations

from datetime import datetime

from engine.models import CheckResult, CheckStatus, Finding
from checks.base import BaseCheck


class AssetInventoryCheck(BaseCheck):
    """Verify technology asset inventory and network map."""

    def execute(self, control_id: str, method: str) -> CheckResult:
        if self.demo:
            return self._demo_check(control_id, method)
        return self._make_result(
            control_id=control_id,
            status=CheckStatus.ERROR.value,
            score=0.0,
            details="Live asset inventory check requires inventory file configuration",
        )

    def _demo_check(self, control_id: str, method: str) -> CheckResult:
        data = self._load_demo_data("asset_inventory.json") or {}
        dispatch = {
            "check_asset_inventory": self._check_asset_inventory,
            "check_network_map": self._check_network_map,
            "check_media_controls": self._check_media_controls,
        }
        handler = dispatch.get(method, self._check_asset_inventory)
        return handler(control_id, data)

    def _check_asset_inventory(self, control_id: str, data: dict) -> CheckResult:
        """Check technology asset inventory completeness."""
        assets = data.get("assets", [])
        last_update = data.get("last_update", "")
        categories_covered = data.get("categories_covered", [])

        findings = []
        score = 1.0

        if not assets:
            return self._make_result(
                control_id=control_id,
                status=CheckStatus.FAIL.value,
                score=0.0,
                findings=[Finding(
                    control_id=control_id,
                    title="No Asset Inventory",
                    description="No technology asset inventory found.",
                    severity="High",
                    cfr_reference="45 CFR § 164.310(d)(2)(iii)",
                    remediation="Create a comprehensive inventory of all technology assets handling ePHI.",
                    estimated_effort="Short-term",
                )],
                details="No asset inventory found",
                decay_days=365,
            )

        # Check last update
        try:
            update_dt = datetime.fromisoformat(last_update)
            days_since = (datetime.now() - update_dt).days
        except (ValueError, TypeError):
            days_since = 999

        if days_since > 365:
            score -= 0.2
            findings.append(Finding(
                control_id=control_id,
                title="Asset Inventory Not Updated",
                description=f"Asset inventory last updated {days_since} days ago. Annual update required.",
                severity="Medium",
                cfr_reference="45 CFR § 164.310(d)(2)(iii)",
                remediation="Update the asset inventory to reflect current state of all ePHI systems.",
                estimated_effort="Short-term",
            ))

        # Check for stale entries
        stale_assets = [a for a in assets if a.get("status") == "stale"]
        if stale_assets:
            score -= 0.05 * len(stale_assets)
            findings.append(Finding(
                control_id=control_id,
                title=f"{len(stale_assets)} Stale Asset Record(s)",
                description=f"Some asset records haven't been verified recently: "
                          f"{', '.join(a.get('hostname', '?') for a in stale_assets[:3])}",
                severity="Low",
                cfr_reference="45 CFR § 164.310(d)(2)(iii)",
                remediation="Verify and update stale asset records.",
                evidence_summary=f"Stale assets: {[a.get('hostname') for a in stale_assets]}",
                estimated_effort="Quick Win",
            ))

        # Check ephi classification
        unclassified = [a for a in assets if not a.get("ephi_classified", False)]
        if unclassified:
            score -= 0.1
            findings.append(Finding(
                control_id=control_id,
                title=f"{len(unclassified)} Asset(s) Missing ePHI Classification",
                description="Some assets lack ePHI classification.",
                severity="Medium",
                cfr_reference="45 CFR § 164.310(d)(2)(iii)",
                remediation="Classify all assets with ePHI handling status.",
                estimated_effort="Quick Win",
            ))

        score = max(0.0, score)
        if not findings:
            status = CheckStatus.PASS.value
        elif score < 0.6:
            status = CheckStatus.FAIL.value
        else:
            status = CheckStatus.PARTIAL.value

        evidence = {
            "total_assets": len(assets),
            "stale_assets": len(stale_assets),
            "last_update": last_update,
            "days_since_update": days_since,
            "categories_covered": categories_covered,
        }

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=evidence, findings=findings,
            details=f"Assets: {len(assets)}, Stale: {len(stale_assets)}, Updated: {days_since}d ago",
            decay_days=365,
        )

    def _check_network_map(self, control_id: str, data: dict) -> CheckResult:
        """Check network map and ePHI data flow documentation."""
        network_map = data.get("network_map", {})

        findings = []
        score = 1.0

        if not network_map.get("exists", False):
            score -= 0.5
            findings.append(Finding(
                control_id=control_id,
                title="No Network Map Documented",
                description="No network map showing ePHI data flows found.",
                severity="High",
                cfr_reference="45 CFR § 164.312(e)(1)",
                remediation="Create a network diagram documenting all ePHI data flows, "
                          "entry/exit points, and storage locations.",
                estimated_effort="Short-term",
            ))

        if not network_map.get("data_flows_documented", False):
            score -= 0.2
            findings.append(Finding(
                control_id=control_id,
                title="ePHI Data Flows Not Documented",
                description="Data flow mapping for ePHI movement is incomplete.",
                severity="Medium",
                cfr_reference="45 CFR § 164.312(e)(1)",
                remediation="Document all ePHI data flows including source, destination, "
                          "transport method, and encryption status.",
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
            "network_map_exists": network_map.get("exists", False),
            "data_flows_documented": network_map.get("data_flows_documented", False),
            "last_update": network_map.get("last_update", "Unknown"),
        }

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=evidence, findings=findings,
            details=f"Network map: {'exists' if network_map.get('exists') else 'missing'}",
            decay_days=365,
        )

    def _check_media_controls(self, control_id: str, data: dict) -> CheckResult:
        """Check device and media controls."""
        media = data.get("media_controls", {})

        findings = []
        score = 1.0

        if not media.get("disposal_procedures", False):
            score -= 0.3
            findings.append(Finding(
                control_id=control_id,
                title="No Media Disposal Procedures",
                description="No documented procedures for secure media disposal.",
                severity="Medium",
                cfr_reference="45 CFR § 164.310(d)",
                remediation="Implement secure media disposal procedures including certificate of destruction.",
                estimated_effort="Short-term",
            ))

        if not media.get("encryption_portable", False):
            score -= 0.3
            findings.append(Finding(
                control_id=control_id,
                title="Portable Media Not Encrypted",
                description="Portable storage devices are not required to be encrypted.",
                severity="High",
                cfr_reference="45 CFR § 164.310(d)",
                remediation="Enforce encryption on all portable storage devices. Block unencrypted USB devices.",
                estimated_effort="Short-term",
            ))

        score = max(0.0, score)
        if not findings:
            status = CheckStatus.PASS.value
        elif score < 0.5:
            status = CheckStatus.FAIL.value
        else:
            status = CheckStatus.PARTIAL.value

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=media, findings=findings,
            details=f"Media controls: disposal={'yes' if media.get('disposal_procedures') else 'no'}, "
                   f"encryption={'yes' if media.get('encryption_portable') else 'no'}",
            decay_days=365,
        )

    def get_evidence(self) -> dict:
        return self._evidence
