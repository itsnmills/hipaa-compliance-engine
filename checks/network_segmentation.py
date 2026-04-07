"""Network Segmentation verification check module."""

from __future__ import annotations

from engine.models import CheckResult, CheckStatus, Finding
from checks.base import BaseCheck


class NetworkSegmentationCheck(BaseCheck):
    """Verify ePHI systems are segmented from general network."""

    def execute(self, control_id: str, method: str) -> CheckResult:
        if self.demo:
            return self._demo_check(control_id, method)
        return self._live_check(control_id, method)

    def _live_check(self, control_id: str, method: str) -> CheckResult:
        """Live mode: load evidence from user-configured file path."""
        data = self._load_evidence_file("network_topology")
        if data is None:
            return self._make_not_configured_result(control_id, "network_topology", 180)
        return self._check_network_segmentation(control_id, data)


    def _demo_check(self, control_id: str, method: str) -> CheckResult:
        data = self._load_demo_data("network_topology.json") or {}
        return self._check_network_segmentation(control_id, data)

    def _check_network_segmentation(self, control_id: str, data: dict) -> CheckResult:
        """Check network segmentation status."""
        segments = data.get("segments", [])
        firewall_rules = data.get("firewall_rules", [])
        segmentation_tests = data.get("segmentation_tests", [])

        findings = []
        score = 1.0

        # Check VLAN isolation
        ephi_segments = [s for s in segments if s.get("ephi", False)]
        non_ephi_segments = [s for s in segments if not s.get("ephi", False)]

        if not ephi_segments:
            score = 0.0
            findings.append(Finding(
                control_id=control_id,
                title="No ePHI Network Segmentation",
                description="No dedicated network segments identified for ePHI systems.",
                severity="Critical",
                cfr_reference="45 CFR § 164.312(a)(2)(vi)",
                remediation="Implement VLAN-based network segmentation to isolate ePHI systems.",
                estimated_effort="Strategic",
            ))

        # Check for inter-segment rules that might allow lateral movement
        lateral_risks = data.get("lateral_movement_risks", [])
        for risk in lateral_risks:
            score -= 0.15
            findings.append(Finding(
                control_id=control_id,
                title=f"Lateral Movement Risk: {risk.get('description', 'Unknown')}",
                description=f"Potential lateral movement path detected between "
                          f"{risk.get('source_segment', '?')} and {risk.get('target_segment', '?')}: "
                          f"{risk.get('description', '')}",
                severity="High",
                cfr_reference="45 CFR § 164.312(a)(2)(vi)",
                remediation=f"Block {risk.get('protocol', 'traffic')} between "
                          f"{risk.get('source_segment')} and {risk.get('target_segment')}. "
                          f"Implement microsegmentation rules.",
                evidence_summary=f"Source: {risk.get('source_segment')}, Target: {risk.get('target_segment')}",
                estimated_effort="Short-term",
            ))

        # Check if segmentation testing was done
        if not segmentation_tests:
            score -= 0.1
            findings.append(Finding(
                control_id=control_id,
                title="No Segmentation Testing Performed",
                description="No records of segmentation effectiveness testing found.",
                severity="Medium",
                cfr_reference="45 CFR § 164.312(a)(2)(vi)",
                remediation="Conduct segmentation testing to verify isolation effectiveness.",
                estimated_effort="Short-term",
            ))

        score = max(0.0, score)
        if not findings:
            status = CheckStatus.PASS.value
        elif score <= 0.5:
            status = CheckStatus.FAIL.value
        else:
            status = CheckStatus.PARTIAL.value

        evidence = {
            "total_segments": len(segments),
            "ephi_segments": len(ephi_segments),
            "firewall_rules": len(firewall_rules),
            "lateral_risks": len(lateral_risks),
            "segmentation_tests": len(segmentation_tests),
        }

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=evidence, findings=findings,
            details=f"Segments: {len(ephi_segments)} ePHI isolated, {len(lateral_risks)} lateral risks",
            decay_days=180,
        )

    def get_evidence(self) -> dict:
        return self._evidence
