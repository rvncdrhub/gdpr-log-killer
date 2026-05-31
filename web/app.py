"""Flask web application for Wazuh Rule Tracker."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask, jsonify, render_template, request

from wazuh_rule_tracker import db
from wazuh_rule_tracker.diff import FieldChange, RuleChange

DB_PATH = os.environ.get("WAZUH_TRACKER_DB", "wazuh_tracker.db")

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024


def _rule_dict(rule) -> dict | None:
    if rule is None:
        return None
    return {
        "rule_id": rule.rule_id,
        "level": rule.level,
        "attributes": rule.attributes,
        "children": rule.children,
        "parent_groups": rule.parent_groups,
    }


def _serialize_change(c: RuleChange) -> dict:
    return {
        "rule_id": c.rule_id,
        "change_type": c.change_type,
        "old_rule": _rule_dict(c.old_rule),
        "new_rule": _rule_dict(c.new_rule),
        "field_changes": [
            {"field": fc.field, "old": fc.old_value, "new": fc.new_value}
            for fc in c.field_changes
        ],
    }


@app.before_request
def ensure_db():
    db.init_db(DB_PATH)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/versions", methods=["GET"])
def api_list_versions():
    return jsonify(db.list_versions(db_path=DB_PATH))


@app.route("/api/versions", methods=["POST"])
def api_add_version():
    data = request.get_json(force=True, silent=True) or {}
    raw_xml = (data.get("xml") or "").strip()
    label = (data.get("label") or "").strip()
    notes = (data.get("notes") or "").strip()

    if not raw_xml:
        return jsonify({"error": "xml is required"}), 400

    try:
        version = db.add_version(raw_xml, label=label, notes=notes, db_path=DB_PATH)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 422

    return jsonify(version), 201


@app.route("/api/versions/<int:version_id>/raw")
def api_version_raw(version_id: int):
    raw = db.get_version_raw(version_id, db_path=DB_PATH)
    if not raw:
        return jsonify({"error": "not found"}), 404
    return raw, 200, {"Content-Type": "text/xml; charset=utf-8"}


@app.route("/api/diff/<int:from_id>/<int:to_id>")
def api_diff(from_id: int, to_id: int):
    from_summary = db.get_version_summary(from_id, db_path=DB_PATH)
    to_summary = db.get_version_summary(to_id, db_path=DB_PATH)
    if not from_summary or not to_summary:
        return jsonify({"error": "version not found"}), 404

    diff = db.compute_diff(from_id, to_id, db_path=DB_PATH)
    return jsonify({
        "from_version": from_summary,
        "to_version": to_summary,
        "summary": diff.summary(),
        "changes": [_serialize_change(c) for c in diff.changes],
    })


@app.route("/api/versions/<int:version_id>", methods=["DELETE"])
def api_delete_version(version_id: int):
    if db.delete_version(version_id, db_path=DB_PATH):
        return "", 204
    return jsonify({"error": "not found"}), 404


if __name__ == "__main__":
    db.init_db(DB_PATH)
    app.run(debug=True, host="0.0.0.0", port=5001)
