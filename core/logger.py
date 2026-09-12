"""
CHAKRAVYUH - Attack Logger
==========================

This module handles all attack data persistence using SQLite.
It provides a thread-safe logging API used by all listeners.

Key Features:
    - Thread-safe writes using an internal lock
    - Asynchronous geo-location enrichment (background thread)
    - Pattern recognition applied at insert time
    - Structured schema for analysis and export

Author: CHAKRAVYUH Project
Version: 2.0.0
"""

import sqlite3
import json
import threading
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Database Configuration
# ---------------------------------------------------------------------------

DB_PATH = Path("logs/attacks.db")
DB_PATH.parent.mkdir(exist_ok=True)

# Global lock ensures thread-safe writes when multiple listeners log
# attacks concurrently.
_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Schema Initialization
# ---------------------------------------------------------------------------

def init_db() -> None:
    """
    Create the attacks table if it does not already exist.

    The schema stores both raw attack data and enriched metadata
    (geolocation, pattern recognition) for comprehensive analysis.
    """
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS attacks (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp           TEXT,
                src_ip              TEXT,
                src_port            INTEGER,
                protocol            TEXT,
                port                INTEGER,
                event_type          TEXT,
                username            TEXT,
                password            TEXT,
                payload             TEXT,
                user_agent          TEXT,
                raw_data            TEXT,
                geo_country         TEXT,
                geo_city            TEXT,
                geo_isp             TEXT,
                pattern_type        TEXT,
                pattern_tool        TEXT,
                pattern_severity    TEXT,
                pattern_indicators  TEXT
            )
        """)
        conn.commit()


# ---------------------------------------------------------------------------
# Logging API
# ---------------------------------------------------------------------------

def log_attack(**kwargs) -> None:
    """
    Log an attack event to the database with automatic enrichment.

    This function is thread-safe. It stores the primary attack record,
    then asynchronously enriches the record with:
        1. Geolocation data (country, city, ISP)
        2. Attack pattern recognition (tool, severity, indicators)

    Parameters
    ----------
    **kwargs : dict
        Attack attributes. Recognized keys:
            src_ip, src_port, protocol, port, event_type,
            username, password, payload, user_agent, raw_data
    """
    kwargs.setdefault("timestamp", datetime.utcnow().isoformat())

    with _lock, sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT INTO attacks
            (timestamp, src_ip, src_port, protocol, port, event_type,
             username, password, payload, user_agent, raw_data)
            VALUES (:timestamp, :src_ip, :src_port, :protocol, :port,
                    :event_type, :username, :password, :payload,
                    :user_agent, :raw_data)
        """, {k: kwargs.get(k) for k in [
            "timestamp", "src_ip", "src_port", "protocol", "port",
            "event_type", "username", "password", "payload",
            "user_agent", "raw_data"
        ]})
        conn.commit()

        # Retrieve the auto-generated row ID for enrichment
        attack_id = conn.execute(
            "SELECT last_insert_rowid()"
        ).fetchone()[0]

    # -------------------------------------------------------------------
    # Asynchronous Enrichment (runs in background so listeners stay fast)
    # -------------------------------------------------------------------
    _enrich_attack_async(attack_id, kwargs)


def _enrich_attack_async(attack_id: int, attack_data: dict) -> None:
    """
    Launch a background thread to enrich the attack record.

    Enrichment includes geolocation and pattern recognition. This is
    done asynchronously to avoid blocking the listener threads.
    """
    def worker():
        # 1. Geolocation lookup
        try:
            from core.geoip import get_geo
            geo = get_geo(attack_data.get("src_ip", ""))
            with sqlite3.connect(DB_PATH) as c:
                c.execute("""
                    UPDATE attacks
                       SET geo_country = ?, geo_city = ?, geo_isp = ?
                     WHERE id = ?
                """, (geo["country"], geo["city"], geo["isp"], attack_id))
                c.commit()
        except Exception as exc:
            print(f"[Logger] Geolocation failed for #{attack_id}: {exc}")

        # 2. Pattern recognition
        try:
            from core.patterns import analyze_attack_pattern
            pattern = analyze_attack_pattern(
                protocol=attack_data.get("protocol", ""),
                user_agent=attack_data.get("user_agent", ""),
                username=attack_data.get("username", ""),
                password=attack_data.get("password", ""),
                raw_data=attack_data.get("raw_data", "")
            )
            with sqlite3.connect(DB_PATH) as c:
                c.execute("""
                    UPDATE attacks
                       SET pattern_type = ?, pattern_tool = ?,
                           pattern_severity = ?, pattern_indicators = ?
                     WHERE id = ?
                """, (
                    pattern["type"], pattern["tool"], pattern["severity"],
                    json.dumps(pattern["indicators"]), attack_id
                ))
                c.commit()
        except Exception as exc:
            print(f"[Logger] Pattern analysis failed for #{attack_id}: {exc}")

    threading.Thread(target=worker, daemon=True).start()


# ---------------------------------------------------------------------------
# Query API
# ---------------------------------------------------------------------------

def get_recent_attacks(limit: int = 100) -> list:
    """
    Return the most recent attacks as a list of dictionaries.
    """
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM attacks ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]


def get_stats() -> dict:
    """
    Return aggregate statistics about captured attacks.
    """
    with sqlite3.connect(DB_PATH) as conn:
        total = conn.execute("SELECT COUNT(*) FROM attacks").fetchone()[0]
        http = conn.execute(
            "SELECT COUNT(*) FROM attacks WHERE protocol = 'HTTP'"
        ).fetchone()[0]
        ftp = conn.execute(
            "SELECT COUNT(*) FROM attacks WHERE protocol = 'FTP'"
        ).fetchone()[0]
        ssh = conn.execute(
            "SELECT COUNT(*) FROM attacks WHERE protocol = 'SSH'"
        ).fetchone()[0]
    return {"total": total, "http": http, "ftp": ftp, "ssh": ssh}