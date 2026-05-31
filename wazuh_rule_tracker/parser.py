"""
Parse Wazuh XML rule files into structured WazuhRule objects.

A Wazuh rule file is structured as one or more <group name="..."> elements,
each containing <rule id="..." level="..."> children.  Rules may also appear
at the top level when the root element is itself a <group>.
"""

from __future__ import annotations

from dataclasses import dataclass
from xml.etree import ElementTree as ET


@dataclass
class WazuhRule:
    rule_id: int
    level: int
    attributes: dict[str, str]       # XML attributes other than id / level
    children: dict[str, list[str]]   # child tag -> list of stripped text values
    parent_groups: list[str]         # names split from ancestor <group name="...">
    raw_xml: str                     # serialised XML of the <rule> element


def parse_rule_file(xml_text: str) -> list[WazuhRule]:
    """
    Parse raw XML and return all rules found, sorted by rule ID.
    Raises ValueError for malformed XML.
    """
    text = xml_text.strip()
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid XML: {exc}") from exc

    rules: list[WazuhRule] = []
    seen_ids: set[int] = set()

    # Support root = <group ...>, <ossec_config>, or any arbitrary wrapper
    groups: list[ET.Element] = (
        [root] if root.tag == "group" else list(root.iter("group"))
    )
    if not groups:
        groups = [root]

    for group_elem in groups:
        parent_groups = _split_group_name(group_elem.get("name", ""))
        for rule_elem in group_elem.findall("rule"):
            rule = _parse_rule(rule_elem, parent_groups)
            if rule.rule_id not in seen_ids:
                rules.append(rule)
                seen_ids.add(rule.rule_id)

    return sorted(rules, key=lambda r: r.rule_id)


def rules_to_dict(rules: list[WazuhRule]) -> dict[int, WazuhRule]:
    return {r.rule_id: r for r in rules}


def _split_group_name(name_attr: str) -> list[str]:
    return [g.strip() for g in name_attr.split(",") if g.strip()]


def _parse_rule(elem: ET.Element, parent_groups: list[str]) -> WazuhRule:
    try:
        rule_id = int(elem.get("id", 0))
        level = int(elem.get("level", 0))
    except ValueError:
        rule_id = 0
        level = 0

    attrs = {k: v for k, v in elem.attrib.items() if k not in ("id", "level")}

    children: dict[str, list[str]] = {}
    for child in elem:
        inner = _elem_to_text(child)
        children.setdefault(child.tag, []).append(inner)

    return WazuhRule(
        rule_id=rule_id,
        level=level,
        attributes=attrs,
        children=children,
        parent_groups=parent_groups,
        raw_xml=ET.tostring(elem, encoding="unicode"),
    )


def _elem_to_text(elem: ET.Element) -> str:
    if len(elem) == 0:
        return (elem.text or "").strip()
    parts = []
    if elem.text and elem.text.strip():
        parts.append(elem.text.strip())
    for child in elem:
        parts.append(f"<{child.tag}>{_elem_to_text(child)}</{child.tag}>")
    return " ".join(parts)
