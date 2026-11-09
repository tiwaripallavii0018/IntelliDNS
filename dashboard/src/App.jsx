import { useEffect, useState } from "react";
import "./App.css";

const API = "http://127.0.0.1:8000";

function App() {
    const [stats, setStats] = useState({});
    const [queries, setQueries] = useState([]);
    const [domains, setDomains] = useState([]);
    const [alerts, setAlerts] = useState([]);
    const [securityStats, setSecurityStats] = useState({});
    const [incidents, setIncidents] = useState([]);
    const [blockedIps, setBlockedIps] = useState([]);
    const [lastUpdated, setLastUpdated] = useState("");

    const [message, setMessage] = useState("");
    const [loading, setLoading] = useState(false);

    async function fetchData(url) {
        const response = await fetch(API + url);

        if (!response.ok) {
            throw new Error("API request failed: " + url);
        }

        return response.json();
    }

    async function loadData() {
        try {
            const results = await Promise.all([
                fetchData("/api/stats"),
                fetchData("/api/queries"),
                fetchData("/api/top-domains"),
                fetchData("/api/alerts"),
                fetchData("/api/security-stats"),
                fetchData("/api/incidents"),
                fetchData("/api/blocked-ips")
            ]);

            setStats(results[0] || {});
            setQueries(results[1] || []);
            setDomains(results[2] || []);
            setAlerts(results[3] || []);
            setSecurityStats(results[4] || {});
            setIncidents(results[5] || []);
            setBlockedIps(results[6] || []);

            setLastUpdated(new Date().toLocaleTimeString());
        } catch (error) {
            setMessage("Unable to connect to IntelliDNS API.");
            console.error(error);
        }
    }

    useEffect(() => {
        loadData();

        const interval = setInterval(loadData, 5000);

        return () => clearInterval(interval);
    }, []);

    async function acknowledgeIncident(id) {
        try {
            setLoading(true);

            const response = await fetch(
                `${API}/api/incidents/${id}/acknowledge`,
                { method: "POST" }
            );

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || "Action failed");
            }

            setMessage("Incident #" + id + " acknowledged.");
            await loadData();
        } catch (error) {
            setMessage(error.message);
        } finally {
            setLoading(false);
        }
    }

    async function resolveIncident(id) {
        const note = window.prompt(
            "Enter resolution note:",
            "Resolved by administrator"
        );

        if (note === null) return;

        try {
            setLoading(true);

            const response = await fetch(
                `${API}/api/incidents/${id}/resolve`,
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({ note })
                }
            );

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || "Action failed");
            }

            setMessage("Incident #" + id + " resolved.");
            await loadData();
        } catch (error) {
            setMessage(error.message);
        } finally {
            setLoading(false);
        }
    }

    async function unblockIP(ip) {
        if (!window.confirm("Unblock " + ip + "?")) return;

        try {
            setLoading(true);

            const response = await fetch(
                `${API}/api/blocked-ips/${encodeURIComponent(ip)}`,
                { method: "DELETE" }
            );

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || "Unblock failed");
            }

            setMessage(ip + " unblocked successfully.");
            await loadData();
        } catch (error) {
            setMessage(error.message);
        } finally {
            setLoading(false);
        }
    }

    const severity = securityStats.severity || {};
    const incidentCounts = securityStats.incidents || {};

    return (
        <div className="app">
            <header className="header">
                <div>
                    <h1>IntelliDNS</h1>
                    <p>Intelligent DNS Security Dashboard</p>
                </div>

                <div className="header-right">
                    <span className="live-dot"></span>
                    System Live
                    <button onClick={loadData}>Refresh</button>
                </div>
            </header>

            <main className="container">
                {message && (
                    <div className="message">
                        <span>{message}</span>
                        <button onClick={() => setMessage("")}>×</button>
                    </div>
                )}

                <section>
                    <h2>Network Overview</h2>

                    <div className="cards">
                        <div className="card">
                            <span>Total DNS Queries</span>
                            <strong>{stats.total_queries || 0}</strong>
                        </div>

                        <div className="card">
                            <span>Blocked Queries</span>
                            <strong>{stats.blocked_queries || 0}</strong>
                        </div>

                        <div className="card">
                            <span>Average Response Time</span>
                            <strong>
                                {Number(stats.avg_response_time || 0).toFixed(4)} s
                            </strong>
                        </div>

                        <div className="card">
                            <span>Active IP Blocks</span>
                            <strong>{blockedIps.length}</strong>
                        </div>
                    </div>
                </section>

                <section>
                    <h2>Security Overview</h2>

                    <div className="cards">
                        <div className="card severity-low">
                            <span>Low Alerts</span>
                            <strong>{severity.LOW || 0}</strong>
                        </div>

                        <div className="card severity-medium">
                            <span>Medium Alerts</span>
                            <strong>{severity.MEDIUM || 0}</strong>
                        </div>

                        <div className="card severity-high">
                            <span>High Alerts</span>
                            <strong>{severity.HIGH || 0}</strong>
                        </div>

                        <div className="card severity-critical">
                            <span>Critical Alerts</span>
                            <strong>{severity.CRITICAL || 0}</strong>
                        </div>
                    </div>
                </section>

                <section>
                    <h2>Incident Management</h2>

                    <div className="cards">
                        <div className="card">
                            <span>Open</span>
                            <strong>{incidentCounts.OPEN || 0}</strong>
                        </div>

                        <div className="card">
                            <span>Acknowledged</span>
                            <strong>{incidentCounts.ACKNOWLEDGED || 0}</strong>
                        </div>

                        <div className="card">
                            <span>Resolved</span>
                            <strong>{incidentCounts.RESOLVED || 0}</strong>
                        </div>
                    </div>

                    <div className="panel">
                        <div className="panel-heading">
                            <h3>All Incidents</h3>
                            <span>{incidents.length} records</span>
                        </div>

                        <div className="table-wrap">
                            <table>
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>Title</th>
                                        <th>Client IP</th>
                                        <th>Domain</th>
                                        <th>Severity</th>
                                        <th>Status</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>

                                <tbody>
                                    {incidents.map((incident) => (
                                        <tr key={incident.id}>
                                            <td>#{incident.id}</td>
                                            <td>{incident.title}</td>
                                            <td>{incident.client_ip}</td>
                                            <td>{incident.domain}</td>
                                            <td>
                                                <span className={
                                                    "tag " +
                                                    String(incident.severity).toLowerCase()
                                                }>
                                                    {incident.severity}
                                                </span>
                                            </td>
                                            <td>
                                                <span className={
                                                    "tag " +
                                                    String(incident.status).toLowerCase()
                                                }>
                                                    {incident.status}
                                                </span>
                                            </td>
                                            <td>
                                                {incident.status === "OPEN" && (
                                                    <button
                                                        disabled={loading}
                                                        onClick={() =>
                                                            acknowledgeIncident(incident.id)
                                                        }
                                                    >
                                                        Acknowledge
                                                    </button>
                                                )}

                                                {incident.status !== "RESOLVED" && (
                                                    <button
                                                        className="resolve-button"
                                                        disabled={loading}
                                                        onClick={() =>
                                                            resolveIncident(incident.id)
                                                        }
                                                    >
                                                        Resolve
                                                    </button>
                                                )}
                                            </td>
                                        </tr>
                                    ))}

                                    {incidents.length === 0 && (
                                        <tr>
                                            <td colSpan="7" className="empty">
                                                No incidents found.
                                            </td>
                                        </tr>
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </section>

                <section>
                    <h2>Blocked IP Addresses</h2>

                    <div className="panel">
                        <div className="panel-heading">
                            <h3>Active Blocks</h3>
                            <span>{blockedIps.length} active</span>
                        </div>

                        <div className="table-wrap">
                            <table>
                                <thead>
                                    <tr>
                                        <th>IP Address</th>
                                        <th>Reason</th>
                                        <th>Duration</th>
                                        <th>Expires At</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>

                                <tbody>
                                    {blockedIps.map((item) => (
                                        <tr key={item.id}>
                                            <td>{item.client_ip}</td>
                                            <td>{item.reason}</td>
                                            <td>{item.duration}s</td>
                                            <td>{item.expires_at}</td>
                                            <td>
                                                <button
                                                    className="resolve-button"
                                                    disabled={loading}
                                                    onClick={() =>
                                                        unblockIP(item.client_ip)
                                                    }
                                                >
                                                    Unblock
                                                </button>
                                            </td>
                                        </tr>
                                    ))}

                                    {blockedIps.length === 0 && (
                                        <tr>
                                            <td colSpan="5" className="empty">
                                                No active IP blocks.
                                            </td>
                                        </tr>
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </section>

                <section>
                    <h2>Recent Security Alerts</h2>

                    <div className="panel">
                        <div className="table-wrap">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Type</th>
                                        <th>Client IP</th>
                                        <th>Domain</th>
                                        <th>Severity</th>
                                        <th>Time</th>
                                    </tr>
                                </thead>

                                <tbody>
                                    {alerts.map((alert) => (
                                        <tr key={alert.id}>
                                            <td>{alert.alert_type}</td>
                                            <td>{alert.client_ip}</td>
                                            <td>{alert.domain}</td>
                                            <td>{alert.severity}</td>
                                            <td>{alert.timestamp}</td>
                                        </tr>
                                    ))}

                                    {alerts.length === 0 && (
                                        <tr>
                                            <td colSpan="5" className="empty">
                                                No security alerts found.
                                            </td>
                                        </tr>
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </section>

                <section>
                    <h2>Most Queried Domains</h2>

                    <div className="panel">
                        {domains.map((item, index) => (
                            <div className="domain-row" key={item.domain}>
                                <span>{index + 1}. {item.domain}</span>
                                <strong>{item.count}</strong>
                            </div>
                        ))}

                        {domains.length === 0 && (
                            <p className="empty">No domain data available.</p>
                        )}
                    </div>
                </section>

                <section>
                    <h2>Recent DNS Activity</h2>

                    <div className="panel">
                        <div className="table-wrap">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Domain</th>
                                        <th>Client IP</th>
                                        <th>Status</th>
                                        <th>Response Time</th>
                                        <th>Timestamp</th>
                                    </tr>
                                </thead>

                                <tbody>
                                    {queries.map((query) => (
                                        <tr key={query.id}>
                                            <td>{query.domain}</td>
                                            <td>{query.client_ip}</td>
                                            <td>{query.status}</td>
                                            <td>
                                                {Number(query.response_time || 0).toFixed(4)}s
                                            </td>
                                            <td>{query.timestamp}</td>
                                        </tr>
                                    ))}

                                    {queries.length === 0 && (
                                        <tr>
                                            <td colSpan="5" className="empty">
                                                No DNS activity found.
                                            </td>
                                        </tr>
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </section>

                <footer>
                    IntelliDNS | Automated Threat Response & Incident Management
                    <br />
                    Last updated: {lastUpdated || "Waiting for data"}
                </footer>
            </main>
        </div>
    );
}

export default App;