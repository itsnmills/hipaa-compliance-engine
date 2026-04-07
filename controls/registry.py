"""Control Registry — loads and manages HIPAA control definitions."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml

from engine.exceptions import RegistryError
from engine.models import ControlDefinition, Category
from engine.audit_trail import FileAccessTracker

DEFINITIONS_FILE = Path(__file__).resolve().parent / "control_definitions.yaml"


class ControlRegistry:
    """Registry of all HIPAA Security Rule controls."""

    def __init__(self, definitions_path: str | None = None):
        self._controls: dict[str, ControlDefinition] = {}
        path = Path(definitions_path) if definitions_path else DEFINITIONS_FILE
        self._load(path)

    def _load(self, path: Path) -> None:
        """Load control definitions from YAML file."""
        if not path.exists():
            raise RegistryError(f"Control definitions not found: {path}")

        FileAccessTracker.instance().record(
            str(path), "read", "ControlRegistry", "HIPAA control definitions",
        )
        with open(path, "r") as f:
            data = yaml.safe_load(f)

        if not data or "controls" not in data:
            raise RegistryError("Invalid control definitions file")

        for entry in data["controls"]:
            control = ControlDefinition(
                id=entry["id"],
                cfr_reference=entry["cfr_reference"],
                category=entry["category"],
                title=entry["title"],
                description=entry["description"].strip(),
                check_module=entry["check_module"],
                check_method=entry["check_method"],
                severity=entry["severity"],
                frequency=entry["frequency"],
                freshness_decay_days=entry["freshness_decay_days"],
                evidence_required=entry["evidence_required"],
                remediation_guidance=entry["remediation_guidance"].strip(),
            )
            self._controls[control.id] = control

    @property
    def all_controls(self) -> list[ControlDefinition]:
        """Return all controls."""
        return list(self._controls.values())

    def get(self, control_id: str) -> ControlDefinition:
        """Get a control by ID."""
        if control_id not in self._controls:
            raise RegistryError(f"Control not found: {control_id}")
        return self._controls[control_id]

    def get_by_category(self, category: str) -> list[ControlDefinition]:
        """Get all controls in a category."""
        return [c for c in self._controls.values() if c.category == category]

    def get_by_module(self, module_name: str) -> list[ControlDefinition]:
        """Get all controls handled by a specific check module."""
        return [c for c in self._controls.values() if c.check_module == module_name]

    def get_by_severity(self, severity: str) -> list[ControlDefinition]:
        """Get all controls with a given severity."""
        return [c for c in self._controls.values() if c.severity == severity]

    @property
    def categories(self) -> list[str]:
        """Return unique categories."""
        return sorted(set(c.category for c in self._controls.values()))

    @property
    def count(self) -> int:
        """Return total number of controls."""
        return len(self._controls)

    def __len__(self) -> int:
        return self.count

    def __contains__(self, control_id: str) -> bool:
        return control_id in self._controls
