"""
CHAKRAVYUH - Main Application Server
=====================================

Flask application that serves the honeypot dashboard and provides
REST APIs for controlling listeners and retrieving attack logs.

API Endpoints:
    GET  /                - Dashboard UI
    POST /api/start       - Start a honeypot service
    POST /api/stop        - Stop a honeypot service
    GET  /api/logs        - Retrieve recent attacks
    GET  /api/stats       - Retrieve aggregate statistics
    GET  /api/status      - Retrieve running services

Author: CHAKRAVYUH Project
Version: 2.0.0
"""

from flask import Flask, render_template, request, jsonify
from core.logger import init_db, get_recent_attacks, get_stats
from core.manager import manager


app = Flask(__name__)
app.secret_key = "chakravyuh_secret_2026"

# Initialize the database schema at startup
init_db()


# ---------------------------------------------------------------------------
# Dashboard Route
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Serve the main dashboard UI."""
    return render_template("dashboard.html")


# ---------------------------------------------------------------------------
# Service Control APIs
# ---------------------------------------------------------------------------

@app.route("/api/start", methods=["POST"])
def api_start():
    """Start a honeypot service (HTTP, FTP, or SSH)."""
    data = request.json
    success, message = manager.start(
        data["protocol"],
        int(data["port"]),
        data["banner"]
    )
    return jsonify(ok=success, message=message)


@app.route("/api/stop", methods=["POST"])
def api_stop():
    """Stop a running honeypot service."""
    data = request.json
    success, message = manager.stop(data["protocol"])
    return jsonify(ok=success, message=message)


# ---------------------------------------------------------------------------
# Data Retrieval APIs
# ---------------------------------------------------------------------------

@app.route("/api/logs")
def api_logs():
    """Return the most recent attacks."""
    return jsonify(get_recent_attacks(limit=200))


@app.route("/api/stats")
def api_stats():
    """Return aggregate attack statistics."""
    return jsonify(get_stats())


@app.route("/api/status")
def api_status():
    """Return the running state of all services."""
    return jsonify(manager.status())


# ---------------------------------------------------------------------------
# Application Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 62)
    print("  ⚔   C H A K R A V Y U H   ⚔")
    print("  The Trap That Never Releases")
    print("  " + "─" * 58)
    print("  Honeypot Control System v2.0")
    print("  Dashboard: http://127.0.0.1:5000")
    print("=" * 62)

    app.run(host="0.0.0.0", port=5000, debug=False)