"""
SQLite persistence layer for rule-file versions.

Each version stores the raw XML, a JSON-serialised representation of every
parsed rule, a human label and optional notes, and a UTC timestamp.
Diffs are computed on the fly from the stored parsed representations.
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from .diff import DiffResult, diff_rule_sets
from .parser import WazuhRule, parse_rule_file

DEFAULT_DB = os.environ.get("WAZUH_TRACKER_DB", "wazuh_tracker.db")


def _rules_to_json(rules: list[WazuhRule]) -> str:
    return json.dumps([
        {
            "rule_id": r.rule_id,
            "level": r.level,
            "attributes": r.attributes,
            "children": r.children,
            "parent_groups": r.parent_groups,
        }
        for r in rules
    ])


def _rules_from_json(data: str) -> list[WazuhRule]:
    return [
        WazuhRule(
            rule_id=item["rule_id"],
            level=item["level"],
            attributes=item["attributes"],
            children=item["children"],
            parent_groups=item["parent_groups"],
            raw_xml="",
        )
        for item in json.loads(data)
    ]


@contextmanager
def _conn(db_path: str = DEFAULT_DB):
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def init_db(db_path: str = DEFAULT_DB) -> None:
    with _conn(db_path) as con:
        con.executescript("""
            CREATE TABLE IF NOT EXISTS versions (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp    TEXT    NOT NULL,
                label        TEXT    NOT NULL DEFAULT '',
                notes        TEXT    NOT NULL DEFAULT '',
                raw_xml      TEXT    NOT NULL,
                parsed_json  TEXT    NOT NULL,
                rule_count   INTEGER NOT NULL DEFAULT 0
            );
        """)


def add_version(
    raw_xml: str,
    label: str = "",
    notes: str = "",
    db_path: str = DEFAULT_DB,
) -> dict:
    rules = parse_rule_file(raw_xml)
    timestamp = datetime.now(timezone.utc).isoformat()
    with _conn(db_path) as con:
        cur = con.execute(
            """INSERT INTO versions (timestamp, label, notes, raw_xml, parsed_json, rule_count)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (timestamp, label, notes, raw_xml, _rules_to_json(rules), len(rules)),
        )
        new_id = cur.lastrowid
    return get_version_summary(new_id, db_path=db_path)


def delete_version(version_id: int, db_path: str = DEFAULT_DB) -> bool:
    with _conn(db_path) as con:
        cur = con.execute("DELETE FROM versions WHERE id=?", (version_id,))
    return cur.rowcount > 0


def list_versions(db_path: str = DEFAULT_DB) -> list[dict]:
    with _conn(db_path) as con:
        rows = con.execute(
            "SELECT id, timestamp, label, notes, rule_count FROM versions ORDER BY id"
        ).fetchall()
    versions = [dict(r) for r in rows]
    for i, v in enumerate(versions):
        if i == 0:
            v["diff_summary"] = None
        else:
            diff = compute_diff(versions[i - 1]["id"], v["id"], db_path=db_path)
            v["diff_summary"] = diff.summary()
    return versions


def get_version_summary(version_id: int, db_path: str = DEFAULT_DB) -> dict:
    with _conn(db_path) as con:
        row = con.execute(
            "SELECT id, timestamp, label, notes, rule_count FROM versions WHERE id=?",
            (version_id,),
        ).fetchone()
    return dict(row) if row else {}


def get_version_rules(version_id: int, db_path: str = DEFAULT_DB) -> list[WazuhRule]:
    with _conn(db_path) as con:
        row = con.execute(
            "SELECT parsed_json FROM versions WHERE id=?", (version_id,)
        ).fetchone()
    return _rules_from_json(row["parsed_json"]) if row else []


def get_version_raw(version_id: int, db_path: str = DEFAULT_DB) -> str:
    with _conn(db_path) as con:
        row = con.execute(
            "SELECT raw_xml FROM versions WHERE id=?", (version_id,)
        ).fetchone()
    return row["raw_xml"] if row else ""


def compute_diff(
    from_id: int,
    to_id: int,
    db_path: str = DEFAULT_DB,
) -> DiffResult:
    return diff_rule_sets(
        get_version_rules(from_id, db_path=db_path),
        get_version_rules(to_id, db_path=db_path),
    )
