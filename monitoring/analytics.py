from monitoring.database import get_connection


def get_dashboard_stats():

    conn = get_connection()

    total = conn.execute(
        "SELECT COUNT(*) FROM queries"
    ).fetchone()[0]

    blocked = conn.execute(
        "SELECT COUNT(*) FROM queries WHERE status='BLOCKED'"
    ).fetchone()[0]

    allowed = conn.execute(
        "SELECT COUNT(*) FROM queries WHERE status='ALLOWED'"
    ).fetchone()[0]

    avg_time = conn.execute(
        "SELECT AVG(response_time) FROM queries"
    ).fetchone()[0]

    conn.close()

    return {
        "total_queries": total,
        "blocked_queries": blocked,
        "allowed_queries": allowed,
        "average_response_time": round(avg_time or 0, 2)
    }


def get_recent_queries():

    conn = get_connection()
    conn.row_factory = None

    rows = conn.execute("""
        SELECT domain, client_ip, status,
               response_time, timestamp
        FROM queries
        ORDER BY id DESC
        LIMIT 20
    """).fetchall()

    conn.close()

    return [
        {
            "domain": row[0],
            "client_ip": row[1],
            "status": row[2],
            "response_time": row[3],
            "timestamp": row[4]
        }
        for row in rows
    ]


def get_top_domains():

    conn = get_connection()

    rows = conn.execute("""
        SELECT domain, COUNT(*) AS total
        FROM queries
        GROUP BY domain
        ORDER BY total DESC
        LIMIT 10
    """).fetchall()

    conn.close()

    return [
        {"domain": row[0], "count": row[1]}
        for row in rows
    ]