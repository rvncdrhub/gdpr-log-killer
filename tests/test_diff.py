import os
from wazuh_rule_tracker.parser import parse_rule_file
from wazuh_rule_tracker.diff import diff_rule_sets

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    with open(os.path.join(FIXTURE, name)) as f:
        return f.read()


def rules(name):
    return parse_rule_file(load(name))


def test_diff_summary():
    d = diff_rule_sets(rules("rules_v1.xml"), rules("rules_v2.xml"))
    s = d.summary()
    assert s["added"] == 1
    assert s["removed"] == 1
    assert s["modified"] == 3
    assert s["total"] == 5


def test_diff_added_ids():
    d = diff_rule_sets(rules("rules_v1.xml"), rules("rules_v2.xml"))
    assert [c.rule_id for c in d.added] == [10004]


def test_diff_removed_ids():
    d = diff_rule_sets(rules("rules_v1.xml"), rules("rules_v2.xml"))
    assert [c.rule_id for c in d.removed] == [10002]


def test_diff_modified_level():
    d = diff_rule_sets(rules("rules_v1.xml"), rules("rules_v2.xml"))
    mod = next(c for c in d.modified if c.rule_id == 10001)
    level_change = next(fc for fc in mod.field_changes if fc.field == "level")
    assert level_change.old_value == "5"
    assert level_change.new_value == "7"


def test_diff_modified_description():
    d = diff_rule_sets(rules("rules_v1.xml"), rules("rules_v2.xml"))
    mod = next(c for c in d.modified if c.rule_id == 10003)
    desc_change = next(fc for fc in mod.field_changes if fc.field == "description")
    assert "updated" in desc_change.new_value


def test_diff_modified_attribute_removed():
    d = diff_rule_sets(rules("rules_v1.xml"), rules("rules_v2.xml"))
    mod = next(c for c in d.modified if c.rule_id == 10005)
    attr_change = next(fc for fc in mod.field_changes if fc.field == "@noalert")
    assert attr_change.old_value == "1"
    assert attr_change.new_value is None


def test_diff_no_changes_identical():
    r = rules("rules_v1.xml")
    d = diff_rule_sets(r, r)
    assert d.summary()["total"] == 0


def test_diff_all_added_empty_old():
    new = rules("rules_v1.xml")
    d = diff_rule_sets([], new)
    assert len(d.added) == len(new)
    assert len(d.removed) == 0
    assert len(d.modified) == 0


def test_diff_all_removed_empty_new():
    old = rules("rules_v1.xml")
    d = diff_rule_sets(old, [])
    assert len(d.removed) == len(old)
    assert len(d.added) == 0


def test_diff_added_rule_has_no_old():
    d = diff_rule_sets(rules("rules_v1.xml"), rules("rules_v2.xml"))
    added = next(c for c in d.added if c.rule_id == 10004)
    assert added.old_rule is None
    assert added.new_rule is not None


def test_diff_removed_rule_has_no_new():
    d = diff_rule_sets(rules("rules_v1.xml"), rules("rules_v2.xml"))
    removed = next(c for c in d.removed if c.rule_id == 10002)
    assert removed.new_rule is None
    assert removed.old_rule is not None
