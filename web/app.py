"""
Flask web application for the GDPR Log Killer.
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask, jsonify, render_template, request

from gdpr_log_killer.sanitizer import Sanitizer

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/sanitize", methods=["POST"])
def sanitize():
    data = request.get_json(force=True, silent=True) or {}

    text = data.get("text", "")
    if not isinstance(text, str):
        return jsonify({"error": "text must be a string"}), 400
    if len(text) > 5 * 1024 * 1024:
        return jsonify({"error": "Input too large (max 5 MB)"}), 413

    opts = data.get("options", {})
    domains_raw: str = opts.get("domains", "")
    internal_domains = [
        d.strip() for d in domains_raw.replace(",", "\n").splitlines() if d.strip()
    ]

    sanitizer = Sanitizer(
        strip_ips=bool(opts.get("strip_ips", True)),
        strip_emails=bool(opts.get("strip_emails", True)),
        strip_macs=bool(opts.get("strip_macs", True)),
        strip_hostnames=bool(opts.get("strip_hostnames", True)),
        strip_users=bool(opts.get("strip_users", True)),
        strip_uuids=bool(opts.get("strip_uuids", False)),
        strip_auth_tokens=bool(opts.get("strip_auth_tokens", True)),
        strip_url_creds=bool(opts.get("strip_url_creds", True)),
        strip_phones=bool(opts.get("strip_phones", True)),
        internal_domains=internal_domains,
    )

    result = sanitizer.sanitize(text)

    return jsonify(
        {
            "sanitized": result.text,
            "stats": result.stats,
            "total": sum(result.stats.values()),
        }
    )


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
