from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from monitoring.database import (
    initialize_database,
    get_recent_alerts,
    get_alert_counts
)

from monitoring.analytics import (
    get_dashboard_stats,
    get_recent_queries,
    get_top_domains
)


app = FastAPI(title="IntelliDNS API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

initialize_database()


@app.get("/")
def home():

    return {
        "message": "IntelliDNS API is running"
    }


@app.get("/api/stats")
def stats():

    return get_dashboard_stats()


@app.get("/api/queries")
def queries():

    return get_recent_queries()


@app.get("/api/top-domains")
def top_domains():

    return get_top_domains()


@app.get("/api/alerts")
def alerts():

    return get_recent_alerts()


@app.get("/api/security-stats")
def security_stats():

    return get_alert_counts()