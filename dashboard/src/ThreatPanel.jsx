import { useEffect, useState } from "react";
import "./ThreatPanel.css";

const API = "http://127.0.0.1:8000";

function ThreatPanel() {
    const [analytics, setAnalytics] = useState({});
    const [events, setEvents] = useState([]);
    const [error, setError] = useState("");

    async function loadThreatData() {
        try {
            const [analyticsResponse, eventsResponse] = await Promise.all([
                fetch(`${API}/api/threat-analytics`),
                fetch(`${API}/api/threat-events?limit=20`)
            ]);

            if (!analyticsResponse.ok || !eventsResponse.ok) {
                throw new Error("Unable to load threat intelligence");
            }

            const analyticsData = await analyticsResponse.json();
            const eventsData = await eventsResponse.json();

            setAnalytics(analyticsData);
            setEvents(eventsData);
            setError("");
        } catch (err) {
            setError(err.message);
        }
    }

    useEffect(() => {
        loadThreatData();

        const timer = setInterval(loadThreatData, 5000);

        return () => clearInterval(timer);
    }, []);

    const severity = analytics.severity || {};
    const categories = analytics.categories || {};

    return (
        <section className="threat-panel">
            <div className="threat-heading">
                <div>
                    <h2>Advanced Threat Intelligence</h2>
                    <p>DNS threat detection and risk analysis</p>
                </div>

                <button onClick={loadThreatData}>
                    Refresh
                </button>
            </div>

            {error && (
                <p className="threat-error">{error}</p>
            )}

            <div className="threat-cards">
                <div className="threat-card">
                    <span>Total Threat Events</span>
                    <strong>{analytics.total_threat_events || 0}</strong>
                </div>

                <div className="threat-card critical">
                    <span>Critical</span>
                    <strong>{severity.CRITICAL || 0}</strong>
                </div>

                <div className="threat-card high">
                    <span>High</span>
                    <strong>{severity.HIGH || 0}</strong>
                </div>

                <div className="threat-card medium">
                    <span>Medium</span>
                    <strong>{severity.MEDIUM || 0}</strong>
                </div>
            </div>

            <div className="threat-section">
                <h3>Threat Categories</h3>

                {Object.keys(categories).length === 0 ? (
                    <p>No threat categories recorded yet.</p>
                ) : (
                    Object.entries(categories).map(([category, count]) => (
                        <div className="threat-category" key={category}>
                            <span>{category.replaceAll("_", " ")}</span>
                            <strong>{count}</strong>
                        </div>
                    ))
                )}
            </div>

            <div className="threat-section">
                <h3>Highest Risk Domains</h3>

                {(analytics.top_domains || []).length === 0 ? (
                    <p>No suspicious domains detected yet.</p>
                ) : (
                    <div className="threat-table-wrapper">
                        <table>
                            <thead>
                                <tr>
                                    <th>Domain</th>
                                    <th>Risk Score</th>
                                    <th>Detections</th>
                                </tr>
                            </thead>

                            <tbody>
                                {analytics.top_domains.map((item) => (
                                    <tr key={item.domain}>
                                        <td>{item.domain}</td>
                                        <td>
                                            <span className={
                                                item.risk_score >= 80
                                                    ? "risk critical-risk"
                                                    : item.risk_score >= 60
                                                        ? "risk high-risk"
                                                        : "risk medium-risk"
                                            }>
                                                {item.risk_score}/100
                                            </span>
                                        </td>
                                        <td>{item.detections}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            <div className="threat-section">
                <h3>Recent Threat Events</h3>

                {events.length === 0 ? (
                    <p>No advanced threat events recorded yet.</p>
                ) : (
                    <div className="threat-table-wrapper">
                        <table>
                            <thead>
                                <tr>
                                    <th>Domain</th>
                                    <th>Client IP</th>
                                    <th>Risk</th>
                                    <th>Severity</th>
                                    <th>Detection Reasons</th>
                                    <th>Time</th>
                                </tr>
                            </thead>

                            <tbody>
                                {events.map((event) => (
                                    <tr key={event.id}>
                                        <td>{event.domain}</td>
                                        <td>{event.client_ip}</td>
                                        <td>{event.risk_score}/100</td>
                                        <td>
                                            <span className={
                                                "threat-severity " +
                                                String(event.severity).toLowerCase()
                                            }>
                                                {event.severity}
                                            </span>
                                        </td>
                                        <td>
                                            {(event.reasons || []).join(", ")}
                                        </td>
                                        <td>{event.timestamp}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            <div className="threat-section">
                <h3>Most Active Threat Clients</h3>

                {(analytics.top_clients || []).length === 0 ? (
                    <p>No suspicious clients recorded yet.</p>
                ) : (
                    (analytics.top_clients || []).map((client) => (
                        <div className="threat-category" key={client.client_ip}>
                            <span>{client.client_ip}</span>
                            <strong>
                                {client.detections} detections
                                {" | "}
                                Max risk: {client.max_risk_score}
                            </strong>
                        </div>
                    ))
                )}
            </div>
        </section>
    );
}

export default ThreatPanel;