# Wazuh Rule Tracker

Maintain a version history of your Wazuh rule files and automatically document every delta between versions — which rules were added, removed, or modified, and exactly which fields changed.

## What it tracks

| Change | What you see |
|---|---|
| New rule added | Full rule with all fields highlighted green |
| Rule removed | Full rule highlighted red |
| Level changed | `level: 5 → 7` |
| Match / regex changed | Before / after side-by-side |
| Description changed | Before / after side-by-side |
| Attribute added/removed | e.g. `@noalert: 1 → (removed)` |
| Any child element changed | `frequency`, `timeframe`, `if_sid`, `group`, `mitre`, … |

---

## Quick start

```bash
pip install -r requirements.txt
python web/app.py
# Open http://localhost:5001
```

1. Paste your current rule file XML and click **Save Version** — this becomes the baseline.
2. Paste the next version of the file whenever it changes.
3. The tracker automatically diffs against the previous version and shows the structured change log.

---

## Web interface

- **Version history** sidebar — click any version to view its diff
- **Compare any two versions** — use the "Compare two versions…" button in the header
- **View raw XML** — opens the stored XML in a new tab
- **Delete versions** — hover a version and click ✕

---

## Python API

```python
from wazuh_rule_tracker.parser import parse_rule_file
from wazuh_rule_tracker.diff import diff_rule_sets

v1_rules = parse_rule_file(open("local_rules_v1.xml").read())
v2_rules = parse_rule_file(open("local_rules_v2.xml").read())

result = diff_rule_sets(v1_rules, v2_rules)
print(result.summary())
# {"added": 1, "removed": 1, "modified": 3, "total": 5}

for change in result.modified:
    print(f"Rule {change.rule_id}:")
    for fc in change.field_changes:
        print(f"  {fc.field}: {fc.old_value!r} → {fc.new_value!r}")
```

---

## REST API

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/versions` | List all versions with diff summaries |
| `POST` | `/api/versions` | Add a new version |
| `GET` | `/api/versions/<id>/raw` | Download raw XML for a version |
| `GET` | `/api/diff/<from_id>/<to_id>` | Structured diff between any two versions |
| `DELETE` | `/api/versions/<id>` | Remove a version |

**POST /api/versions** body:
```json
{
  "xml":   "<group name=\"...\">…</group>",
  "label": "Post-incident update",
  "notes": "Added detection for CVE-2024-1234"
}
```

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `WAZUH_TRACKER_DB` | `wazuh_tracker.db` | Path to the SQLite database file |

---

## Development

```bash
pip install -e ".[dev]"
pytest
pytest --cov=wazuh_rule_tracker
```
