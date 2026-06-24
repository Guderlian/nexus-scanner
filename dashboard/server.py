"""Flask Web Dashboard for Nexus P3 - multi-tenant with charts."""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify, render_template, request, Response

app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), "templates"))

_store = None
_cache = None
_projects: dict[str, dict] = {}  # project_id -> {name, created_at, scans}


def set_store(store):
    global _store
    _store = store


def set_cache(cache):
    global _cache
    _cache = cache


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def api_stats():
    stats = {
        "store": _store.get_stats() if _store else {},
        "cache": _cache.stats() if _cache else {},
    }
    return jsonify(stats)


@app.route("/api/sessions")
def api_sessions():
    if _store is None:
        return jsonify({"sessions": []})
    return jsonify({"sessions": _store.list_sessions()})


@app.route("/api/session/<session_id>")
def api_session(session_id):
    if _store is None:
        return jsonify({"error": "store not initialized"}), 404
    session = _store.load_session(session_id)
    if session is None:
        return jsonify({"error": "session not found"}), 404
    return jsonify(session)


@app.route("/api/live")
def api_live():
    def generate():
        yield f"data: {json.dumps({'status': 'idle'})}\n\n"
    return Response(generate(), mimetype="text/event-stream")


# === P3 Multi-tenant routes ===

@app.route("/projects", methods=["GET"])
def list_projects():
    return jsonify({"projects": list(_projects.values())})


@app.route("/projects", methods=["POST"])
def create_project():
    data = request.get_json(silent=True) or {}
    name = data.get("name", f"project-{len(_projects)+1}")
    pid = f"proj-{len(_projects)+1:03d}"
    _projects[pid] = {
        "id": pid,
        "name": name,
        "created_at": datetime.utcnow().isoformat(),
        "scans": [],
    }
    return jsonify(_projects[pid]), 201


@app.route("/projects/<project_id>/scans")
def project_scans(project_id):
    proj = _projects.get(project_id)
    if not proj:
        return jsonify({"error": "project not found"}), 404
    return jsonify({"scans": proj.get("scans", [])})


@app.route("/scan/<scan_id>/report")
def scan_report(scan_id):
    if _store is None:
        return jsonify({"error": "store not initialized"}), 404
    session = _store.load_session(scan_id)
    if session is None:
        return jsonify({"error": "scan not found"}), 404
    return render_template("report.html", scan=session)


@app.route("/api/trends")
def api_trends():
    """Vulnerability trend data (by date)."""
    if _store is None:
        return jsonify({"trends": []})
    sessions = _store.list_sessions()
    by_date = {}
    for s in sessions:
        date = (s.get("created_at") or "")[:10]
        if date:
            by_date[date] = by_date.get(date, 0) + (s.get("evidence_count") or 0)
    trends = [{"date": d, "vulns": v} for d, v in sorted(by_date.items())]
    return jsonify({"trends": trends})


@app.route("/api/vuln_distribution")
def api_vuln_distribution():
    """Vulnerability type distribution."""
    # Placeholder: in production this would aggregate from real data
    return jsonify({
        "distribution": {
            "SSRF": 0, "SQLI": 0, "IDOR": 0, "XSS": 0,
            "SSTI": 0, "XXE": 0, "PATH_TRAVERSAL": 0, "DESERIALIZATION": 0,
        }
    })


@app.route("/api/export/<scan_id>/pdf")
def export_pdf(scan_id):
    return jsonify({"status": "not_implemented", "scan_id": scan_id}), 501


def create_app(store=None, cache=None):
    if store:
        set_store(store)
    if cache:
        set_cache(cache)
    return app
