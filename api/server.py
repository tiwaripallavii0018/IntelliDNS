import ipaddress

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from monitoring.database import (
    initialize_database,
    get_recent_queries,
    get_recent_alerts,
    get_query_stats,
    get_top_domains,
    get_security_stats,
    get_incidents,
    get_incident,
    acknowledge_incident,
    resolve_incident,
    get_ip_blocks
)

from monitoring.threat_store import (
    initialize_threat_store,
    get_threat_events,
    get_threat_analytics
)

from security.response_manager import ThreatResponseManager


app = FastAPI(
    title="IntelliDNS API",
    description="Intelligent DNS Security and Threat Response",
    version="3.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

initialize_database()
initialize_threat_store()

response_manager = ThreatResponseManager(
    default_block_duration=300
)


class BlockIPRequest(BaseModel):
    ip: str
    reason: str = "Manual security block"
    duration: int = Field(default=300, ge=1, le=86400)


class ResolveRequest(BaseModel):
    note: str = "Resolved by administrator"


def validate_ip(ip):
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid IP address"
        )


@app.get("/")
def home():
    return {
        "name": "IntelliDNS",
        "status": "running",
        "version": "3.0.0"
    }


@app.get("/api/stats")
def stats():
    return get_query_stats()


@app.get("/api/queries")
def queries(limit: int = Query(default=100, ge=1, le=500)):
    return get_recent_queries(limit)


@app.get("/api/top-domains")
def top_domains(limit: int = Query(default=10, ge=1, le=100)):
    return get_top_domains(limit)


@app.get("/api/alerts")
def alerts(limit: int = Query(default=50, ge=1, le=500)):
    return get_recent_alerts(limit)


@app.get("/api/security-stats")
def security_stats():
    return get_security_stats()


@app.get("/api/incidents")
def incidents(
    status: str = None,
    limit: int = Query(default=100, ge=1, le=500)
):
    allowed = ["OPEN", "ACKNOWLEDGED", "RESOLVED"]

    if status and status.upper() not in allowed:
        raise HTTPException(
            status_code=400,
            detail="Invalid incident status"
        )

    return get_incidents(
        status.upper() if status else None,
        limit
    )


@app.get("/api/incidents/{incident_id}")
def incident_detail(incident_id: int):
    incident = get_incident(incident_id)

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    return incident


@app.post("/api/incidents/{incident_id}/acknowledge")
def acknowledge(incident_id: int):
    incident = get_incident(incident_id)

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    if incident["status"] != "OPEN":
        raise HTTPException(
            status_code=400,
            detail="Only OPEN incidents can be acknowledged"
        )

    acknowledge_incident(incident_id)

    return {
        "message": "Incident acknowledged",
        "incident_id": incident_id
    }


@app.post("/api/incidents/{incident_id}/resolve")
def resolve(
    incident_id: int,
    request: ResolveRequest
):
    incident = get_incident(incident_id)

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    if incident["status"] == "RESOLVED":
        raise HTTPException(
            status_code=400,
            detail="Incident is already resolved"
        )

    resolve_incident(
        incident_id,
        request.note
    )

    return {
        "message": "Incident resolved",
        "incident_id": incident_id
    }


@app.get("/api/blocked-ips")
def blocked_ips():
    return response_manager.get_blocked_ips()


@app.post("/api/blocked-ips")
def block_ip(request: BlockIPRequest):
    ip = validate_ip(request.ip)

    return response_manager.block_ip(
        ip,
        request.reason,
        request.duration
    )


@app.delete("/api/blocked-ips/{client_ip}")
def unblock_ip(client_ip: str):
    ip = validate_ip(client_ip)

    result = response_manager.unblock_ip(ip)

    if not result:
        raise HTTPException(
            status_code=404,
            detail="No active block found for this IP"
        )

    return {
        "message": "IP unblocked successfully",
        "ip": ip
    }


@app.get("/api/ip-block-history")
def ip_block_history():
    return get_ip_blocks()


# ----------------------------------
# PHASE 6: ADVANCED THREAT ENDPOINTS
# ----------------------------------

@app.get("/api/threat-events")
def threat_events(
    limit: int = Query(default=100, ge=1, le=500)
):
    return get_threat_events(limit)


@app.get("/api/threat-analytics")
def threat_analytics():
    return get_threat_analytics()


@app.get("/api/threat-health")
def threat_health():
    analytics = get_threat_analytics()

    return {
        "status": "active",
        "total_threat_events": analytics["total_threat_events"],
        "severity_levels": analytics["severity"],
        "categories": analytics["categories"]
    }