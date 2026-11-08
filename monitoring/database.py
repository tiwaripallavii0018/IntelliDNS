import sqlite3
import json
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[1] / "intellidns.db"


def get_connection():

    conn = sqlite3.connect(DB_PATH, timeout=10)

    conn.row_factory = sqlite3.Row

    return conn


def initialize_database():

    conn = get_connection()

    try:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                client_ip TEXT,
                status TEXT NOT NULL,
                response_time REAL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT NOT NULL,
                client_ip TEXT,
                domain TEXT,
                severity TEXT,
                details TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()

    finally:

        conn.close()


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


def save_alert(alert_type, client_ip, domain, severity, details):

    conn = get_connection()

    try:

        conn.execute("""
            INSERT INTO security_alerts
            (alert_type, client_ip, domain, severity, details)
            VALUES (?, ?, ?, ?, ?)
        """, (
            alert_type,
            client_ip,
            domain,
            severity,
            json.dumps(details)
        ))

        conn.commit()

    finally:

        conn.close()


def get_recent_alerts(limit=50):

    limit = max(1, min(int(limit), 200))

    conn = get_connection()

    try:

        rows = conn.execute("""
            SELECT *
            FROM security_alerts
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

        result = []

        for row in rows:

            item = dict(row)
            item["details"] = json.loads(item["details"])

            result.append(item)

        return result

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