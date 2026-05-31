import os
import pytest
from wazuh_rule_tracker.parser import parse_rule_file, WazuhRule

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    with open(os.path.join(FIXTURE, name)) as f:
        return f.read()


def test_parse_returns_sorted_rules():
    rules = parse_rule_file(load("rules_v1.xml"))
    ids = [r.rule_id for r in rules]
    assert ids == sorted(ids)


def test_parse_rule_count_v1():
    rules = parse_rule_file(load("rules_v1.xml"))
    assert len(rules) == 4


def test_parse_rule_count_v2():
    rules = parse_rule_file(load("rules_v2.xml"))
    assert len(rules) == 4


def test_parse_rule_id_and_level():
    rules = parse_rule_file(load("rules_v1.xml"))
    r = next(r for r in rules if r.rule_id == 10001)
    assert r.level == 5


def test_parse_description():
    rules = parse_rule_file(load("rules_v1.xml"))
    r = next(r for r in rules if r.rule_id == 10001)
    assert r.children["description"] == ["Generic error detected"]


def test_parse_parent_groups():
    rules = parse_rule_file(load("rules_v1.xml"))
    assert "syslog" in rules[0].parent_groups


def test_parse_attributes():
    rules = parse_rule_file(load("rules_v1.xml"))
    r = next(r for r in rules if r.rule_id == 10005)
    assert r.attributes.get("noalert") == "1"


def test_parse_nested_child_mitre():
    rules = parse_rule_file(load("rules_v2.xml"))
    r = next(r for r in rules if r.rule_id == 10004)
    assert "mitre" in r.children


def test_parse_invalid_xml():
    with pytest.raises(ValueError, match="Invalid XML"):
        parse_rule_file("<not closed")


def test_parse_inline_xml():
    xml = """<group name="test,">
      <rule id="99001" level="3">
        <match>test</match>
        <description>Test rule</description>
      </rule>
    </group>"""
    rules = parse_rule_file(xml)
    assert len(rules) == 1
    assert rules[0].rule_id == 99001
    assert rules[0].level == 3
