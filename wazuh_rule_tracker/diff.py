"""
Structured diff between two sets of Wazuh rules.

Rather than a text-level diff, this compares rules at the field level so the
UI can highlight exactly what changed within a rule (level, description, match
expression, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .parser import WazuhRule, rules_to_dict


@dataclass
class FieldChange:
    field: str
    old_value: Any
    new_value: Any


@dataclass
class RuleChange:
    rule_id: int
    change_type: str               # "added" | "removed" | "modified"
    old_rule: WazuhRule | None
    new_rule: WazuhRule | None
    field_changes: list[FieldChange]


@dataclass
class DiffResult:
    changes: list[RuleChange]

    @property
    def added(self) -> list[RuleChange]:
        return [c for c in self.changes if c.change_type == "added"]

    @property
    def removed(self) -> list[RuleChange]:
        return [c for c in self.changes if c.change_type == "removed"]

    @property
    def modified(self) -> list[RuleChange]:
        return [c for c in self.changes if c.change_type == "modified"]

    def summary(self) -> dict[str, int]:
        return {
            "added": len(self.added),
            "removed": len(self.removed),
            "modified": len(self.modified),
            "total": len(self.changes),
        }


def diff_rule_sets(
    old_rules: list[WazuhRule],
    new_rules: list[WazuhRule],
) -> DiffResult:
    old_map = rules_to_dict(old_rules)
    new_map = rules_to_dict(new_rules)
    old_ids = set(old_map)
    new_ids = set(new_map)

    changes: list[RuleChange] = []

    for rule_id in sorted(old_ids - new_ids):
        changes.append(RuleChange(
            rule_id=rule_id,
            change_type="removed",
            old_rule=old_map[rule_id],
            new_rule=None,
            field_changes=[],
        ))

    for rule_id in sorted(new_ids - old_ids):
        changes.append(RuleChange(
            rule_id=rule_id,
            change_type="added",
            old_rule=None,
            new_rule=new_map[rule_id],
            field_changes=[],
        ))

    for rule_id in sorted(old_ids & new_ids):
        fcs = _compare_rules(old_map[rule_id], new_map[rule_id])
        if fcs:
            changes.append(RuleChange(
                rule_id=rule_id,
                change_type="modified",
                old_rule=old_map[rule_id],
                new_rule=new_map[rule_id],
                field_changes=fcs,
            ))

    changes.sort(key=lambda c: c.rule_id)
    return DiffResult(changes=changes)


def _compare_rules(old: WazuhRule, new: WazuhRule) -> list[FieldChange]:
    changes: list[FieldChange] = []

    if old.level != new.level:
        changes.append(FieldChange("level", str(old.level), str(new.level)))

    for key in sorted(set(old.attributes) | set(new.attributes)):
        ov, nv = old.attributes.get(key), new.attributes.get(key)
        if ov != nv:
            changes.append(FieldChange(f"@{key}", ov, nv))

    for key in sorted(set(old.children) | set(new.children)):
        ov_list = old.children.get(key, [])
        nv_list = new.children.get(key, [])
        if ov_list != nv_list:
            changes.append(FieldChange(
                key,
                ov_list[0] if len(ov_list) == 1 else (ov_list or None),
                nv_list[0] if len(nv_list) == 1 else (nv_list or None),
            ))

    if set(old.parent_groups) != set(new.parent_groups):
        changes.append(FieldChange(
            "parent_groups",
            ", ".join(sorted(old.parent_groups)),
            ", ".join(sorted(new.parent_groups)),
        ))

    return changes
