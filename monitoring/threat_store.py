import json

from monitoring.database import get_connection, initialize_database


def initialize_threat_store():
    initialize_database()

    conn = get_connection()

    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS threat_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_ip TEXT,
                domain TEXT,
                risk_score INTEGER,
                severity TEXT,
                category TEXT,
                reasons TEXT,
                details TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_threat_timestamp
            ON threat_events(timestamp)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_threat_client
            ON threat_events(client_ip)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_threat_domain
            ON threat_events(domain)
        """)

        conn.commit()

    finally:
        conn.close()


def save_threat_event(result):
    conn = get_connection()

    try:
        reasons = json.dumps(
            result.get("reasons", []),
            ensure_ascii=False
        )

        details = json.dumps(
            result,
            ensure_ascii=False,
            default=str
        )

        cursor = conn.execute("""
            INSERT INTO threat_events (
                client_ip,
                domain,
                risk_score,
                severity,
                category,
                reasons,
                details
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            result.get("client_ip"),
            result.get("domain"),
            result.get("risk_score", 0),
            result.get("severity", "LOW"),
            result.get("category", "DNS_THREAT"),
            reasons,
            details
        ))

        event_id = cursor.lastrowid
        conn.commit()

        return event_id

    finally:
        conn.close()


def get_threat_events(limit=100):
    conn = get_connection()

    try:
        rows = conn.execute("""
            SELECT *
            FROM threat_events
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

        result = []

        for row in rows:
            item = dict(row)

            try:
                item["reasons"] = json.loads(item["reasons"])
            except (TypeError, json.JSONDecodeError):
                item["reasons"] = []

            try:
                item["details"] = json.loads(item["details"])
            except (TypeError, json.JSONDecodeError):
                item["details"] = {}

            result.append(item)

        return result

    finally:
        conn.close()


def get_threat_analytics():
    conn = get_connection()

    try:
        total = conn.execute("""
            SELECT COUNT(*) FROM threat_events
        """).fetchone()[0]

        severity_rows = conn.execute("""
            SELECT severity, COUNT(*) AS count
            FROM threat_events
            GROUP BY severity
        """).fetchall()

        category_rows = conn.execute("""
            SELECT category, COUNT(*) AS count
            FROM threat_events
            GROUP BY category
        """).fetchall()

        top_domains = conn.execute("""
            SELECT domain, MAX(risk_score) AS risk_score,
                   COUNT(*) AS detections
            FROM threat_events
            GROUP BY domain
            ORDER BY risk_score DESC, detections DESC
            LIMIT 10
        """).fetchall()

        top_clients = conn.execute("""
            SELECT client_ip, COUNT(*) AS detections,
                   MAX(risk_score) AS max_risk_score
            FROM threat_events
            GROUP BY client_ip
            ORDER BY detections DESC
            LIMIT 10
        """).fetchall()

        return {
            "total_threat_events": total,
            "severity": {
                row["severity"]: row["count"]
                for row in severity_rows
            },
            "categories": {
                row["category"]: row["count"]
                for row in category_rows
            },
            "top_domains": [
                dict(row) for row in top_domains
            ],
            "top_clients": [
                dict(row) for row in top_clients
            ]
        }

    finally:
        conn.close()