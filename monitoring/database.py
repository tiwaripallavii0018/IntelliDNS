
import sqlite3
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "intellidns.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            client_ip TEXT,
            status TEXT,
            response_time REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT,
            client_ip TEXT,
            domain TEXT,
            severity TEXT,
            details TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER,
            title TEXT,
            description TEXT,
            client_ip TEXT,
            domain TEXT,
            severity TEXT,
            status TEXT DEFAULT 'OPEN',
            resolution_note TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_ip TEXT NOT NULL,
            reason TEXT,
            duration_seconds INTEGER,
            blocked_at TEXT DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT,
            active INTEGER DEFAULT 1
        )
    """)

    conn.commit()
    conn.close()


# -------------------------------
# DNS QUERY FUNCTIONS
# -------------------------------

def save_query(domain, client_ip, status, response_time):
    conn = get_connection()

    try:
        conn.execute("""
            INSERT INTO queries
            (domain, client_ip, status, response_time)
            VALUES (?, ?, ?, ?)
        """, (domain, client_ip, status, response_time))

        conn.commit()
    finally:
        conn.close()


def get_recent_queries(limit=100):
    conn = get_connection()

    try:
        rows = conn.execute("""
            SELECT * FROM queries
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,)).fetchall()

        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_query_stats():
    conn = get_connection()

    try:
        row = conn.execute("""
            SELECT
                COUNT(*) AS total_queries,
                SUM(
                    CASE WHEN status = 'BLOCKED'
                    THEN 1 ELSE 0 END
                ) AS blocked_queries,
                AVG(response_time) AS avg_response_time
            FROM queries
        """).fetchone()

        return dict(row) if row else {}
    finally:
        conn.close()


def get_top_domains(limit=10):
    conn = get_connection()

    try:
        rows = conn.execute("""
            SELECT domain, COUNT(*) AS count
            FROM queries
            WHERE domain IS NOT NULL
            GROUP BY domain
            ORDER BY count DESC
            LIMIT ?
        """, (limit,)).fetchall()

        return [dict(row) for row in rows]
    finally:
        conn.close()


# -------------------------------
# SECURITY ALERT FUNCTIONS
# -------------------------------

def save_alert(alert_type, client_ip, domain, severity, details):
    conn = get_connection()

    try:
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO security_alerts
            (alert_type, client_ip, domain, severity, details)
            VALUES (?, ?, ?, ?, ?)
        """, (
            alert_type,
            client_ip,
            domain,
            severity,
            str(details)
        ))

        alert_id = cursor.lastrowid
        conn.commit()

        return alert_id
    finally:
        conn.close()


def get_recent_alerts(limit=50):
    conn = get_connection()

    try:
        rows = conn.execute("""
            SELECT * FROM security_alerts
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,)).fetchall()

        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_alert_counts():
    conn = get_connection()

    try:
        rows = conn.execute("""
            SELECT severity, COUNT(*) AS count
            FROM security_alerts
            GROUP BY severity
        """).fetchall()

        return {
            row["severity"]: row["count"]
            for row in rows
        }
    finally:
        conn.close()


# -------------------------------
# INCIDENT FUNCTIONS
# -------------------------------

def create_incident(
    alert_id,
    title,
    description,
    client_ip,
    domain,
    severity
):
    conn = get_connection()

    try:
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO incidents
            (
                alert_id,
                title,
                description,
                client_ip,
                domain,
                severity
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            alert_id,
            title,
            description,
            client_ip,
            domain,
            severity
        ))

        incident_id = cursor.lastrowid
        conn.commit()

        return incident_id
    finally:
        conn.close()


def get_incidents(status=None, limit=100):
    conn = get_connection()

    try:
        if status:
            rows = conn.execute("""
                SELECT * FROM incidents
                WHERE status = ?
                ORDER BY created_at DESC
                LIMIT ?
            """, (status.upper(), limit)).fetchall()
        else:
            rows = conn.execute("""
                SELECT * FROM incidents
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,)).fetchall()

        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_incident(incident_id):
    conn = get_connection()

    try:
        row = conn.execute("""
            SELECT * FROM incidents
            WHERE id = ?
        """, (incident_id,)).fetchone()

        return dict(row) if row else None
    finally:
        conn.close()


def acknowledge_incident(incident_id):
    conn = get_connection()

    try:
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE incidents
            SET status = 'ACKNOWLEDGED',
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'OPEN'
        """, (incident_id,))

        changed = cursor.rowcount
        conn.commit()

        return changed > 0
    finally:
        conn.close()


def resolve_incident(incident_id, resolution_note="Resolved"):
    conn = get_connection()

    try:
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE incidents
            SET status = 'RESOLVED',
                resolution_note = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
              AND status IN ('OPEN', 'ACKNOWLEDGED')
        """, (resolution_note, incident_id))

        changed = cursor.rowcount
        conn.commit()

        return changed > 0
    finally:
        conn.close()


# -------------------------------
# IP BLOCK FUNCTIONS
# -------------------------------

def save_ip_block(client_ip, reason, duration, expires_at):
    conn = get_connection()

    try:
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE ip_blocks
            SET active = 0
            WHERE client_ip = ? AND active = 1
        """, (client_ip,))

        blocked_at = datetime.now().isoformat()

        cursor.execute("""
            INSERT INTO ip_blocks
            (
                client_ip,
                reason,
                duration_seconds,
                blocked_at,
                expires_at,
                active
            )
            VALUES (?, ?, ?, ?, ?, 1)
        """, (
            client_ip,
            reason,
            duration,
            blocked_at,
            str(expires_at)
        ))

        block_id = cursor.lastrowid
        conn.commit()

        return block_id
    finally:
        conn.close()


def deactivate_ip_block(client_ip):
    conn = get_connection()

    try:
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE ip_blocks
            SET active = 0
            WHERE client_ip = ? AND active = 1
        """, (client_ip,))

        changed = cursor.rowcount
        conn.commit()

        return changed > 0
    finally:
        conn.close()


def get_ip_blocks():
    conn = get_connection()

    try:
        rows = conn.execute("""
            SELECT * FROM ip_blocks
            ORDER BY blocked_at DESC
        """).fetchall()

        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_active_ip_blocks():
    conn = get_connection()

    try:
        rows = conn.execute("""
            SELECT * FROM ip_blocks
            WHERE active = 1
              AND datetime(expires_at) > datetime('now', 'localtime')
            ORDER BY blocked_at DESC
        """).fetchall()

        return [dict(row) for row in rows]
    finally:
        conn.close()


def is_ip_blocked(client_ip):
    conn = get_connection()

    try:
        row = conn.execute("""
            SELECT id FROM ip_blocks
            WHERE client_ip = ?
              AND active = 1
              AND datetime(expires_at) > datetime('now', 'localtime')
            ORDER BY blocked_at DESC
            LIMIT 1
        """, (client_ip,)).fetchone()

        return row is not None
    finally:
        conn.close()


# -------------------------------
# SECURITY STATISTICS
# -------------------------------

def get_security_stats():
    conn = get_connection()

    try:
        severity_rows = conn.execute("""
            SELECT severity, COUNT(*) AS count
            FROM security_alerts
            GROUP BY severity
        """).fetchall()

        incident_rows = conn.execute("""
            SELECT status, COUNT(*) AS count
            FROM incidents
            GROUP BY status
        """).fetchall()

        return {
            "severity": {
                row["severity"]: row["count"]
                for row in severity_rows
            },
            "incidents": {
                row["status"]: row["count"]
                for row in incident_rows
            }
        }
    finally:
        conn.close()
