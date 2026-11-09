import { useEffect, useState } from "react";
import "./SecurityPanel.css";

const API = "http://127.0.0.1:8000";

function SecurityPanel() {

    const [blocked, setBlocked] = useState({});
    const [history, setHistory] = useState([]);
    const [incidents, setIncidents] = useState([]);

    const [ip, setIp] = useState("");
    const [reason, setReason] = useState("Manual admin block");

    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");

    async function loadData() {

        try {

            const [blockRes, incidentRes] = await Promise.all([
                fetch(`${API}/api/blocked-ips`),
                fetch(`${API}/api/incidents`)
            ]);

            if (!blockRes.ok || !incidentRes.ok) {
                throw new Error("Unable to load security data");
            }

            const blockData = await blockRes.json();
            const incidentData = await incidentRes.json();

            setBlocked(blockData.blocked_ips || {});
            setHistory(blockData.history || []);
            setIncidents(incidentData || []);

            setError("");

        } catch (err) {

            setError(err.message);

        }
    }

    useEffect(() => {

        loadData();

        const timer = setInterval(loadData, 3000);

        return () => clearInterval(timer);

    }, []);

    async function blockIP() {

        if (!ip.trim()) {
            setError("Enter an IP address");
            return;
        }

        setLoading(true);

        try {

            const response = await fetch(`${API}/api/blocked-ips`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    ip: ip.trim(),
                    duration: 300,
                    reason: reason
                })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || "Unable to block IP");
            }

            setIp("");
            setError("");

            await loadData();

        } catch (err) {

            setError(err.message);

        } finally {

            setLoading(false);

        }
    }

    async function unblockIP(clientIP) {

        try {

            const response = await fetch(
                `${API}/api/blocked-ips/${encodeURIComponent(clientIP)}`,
                { method: "DELETE" }
            );

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || "Unable to unblock IP");
            }

            await loadData();

        } catch (err) {

            setError(err.message);

        }
    }

    async function updateIncident(id, status) {

        try {

            const response = await fetch(
                `${API}/api/incidents/${id}`,
                {
                    method: "PATCH",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({ status })
                }
            );

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || "Unable to update incident");
            }

            await loadData();

        } catch (err) {

            setError(err.message);

        }
    }

    return (

        <section className="security-panel">

            <div className="security-heading">
                <div>
                    <h2>Threat Response Center</h2>
                    <p>Manage blocked clients and security incidents</p>
                </div>

                <button onClick={loadData}>
                    Refresh
                </button>
            </div>

            {error && (
                <div className="security-error">
                    {error}
                </div>
            )}

            <div className="response-stats">

                <div className="response-card">
                    <span>Currently Blocked</span>
                    <h2>{Object.keys(blocked).length}</h2>
                </div>

                <div className="response-card">
                    <span>Total Block Records</span>
                    <h2>{history.length}</h2>
                </div>

                <div className="response-card">
                    <span>Open Incidents</span>
                    <h2>
                        {incidents.filter(
                            item => item.status === "OPEN"
                        ).length}
                    </h2>
                </div>

            </div>

            <div className="response-section">

                <h3>Manual IP Blocking</h3>

                <div className="block-form">

                    <input
                        type="text"
                        placeholder="Enter IP address"
                        value={ip}
                        onChange={e => setIp(e.target.value)}
                    />

                    <input
                        type="text"
                        placeholder="Reason"
                        value={reason}
                        onChange={e => setReason(e.target.value)}
                    />

                    <button
                        onClick={blockIP}
                        disabled={loading}
                    >
                        {loading ? "Blocking..." : "Block IP"}
                    </button>

                </div>

            </div>

            <div className="response-section">

                <h3>Active Blocked IPs</h3>

                {Object.keys(blocked).length === 0 ? (

                    <p className="empty-security">
                        No IP addresses are currently blocked.
                    </p>

                ) : (

                    <div className="security-table-wrapper">

                        <table className="security-table">

                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>Remaining Time</th>
                                    <th>Action</th>
                                </tr>
                            </thead>

                            <tbody>

                                {Object.entries(blocked).map(([clientIP, seconds]) => (

                                    <tr key={clientIP}>
                                        <td>{clientIP}</td>
                                        <td>{seconds} sec</td>
                                        <td>
                                            <button
                                                className="unblock-button"
                                                onClick={() => unblockIP(clientIP)}
                                            >
                                                Unblock
                                            </button>
                                        </td>
                                    </tr>

                                ))}

                            </tbody>

                        </table>

                    </div>

                )}

            </div>

            <div className="response-section">

                <h3>Security Incidents</h3>

                {incidents.length === 0 ? (

                    <p className="empty-security">
                        No incidents available.
                    </p>

                ) : (

                    <div className="security-table-wrapper">

                        <table className="security-table">

                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Type</th>
                                    <th>Client IP</th>
                                    <th>Severity</th>
                                    <th>Status</th>
                                    <th>Action</th>
                                </tr>
                            </thead>

                            <tbody>

                                {incidents.map(item => (

                                    <tr key={item.id}>

                                        <td>#{item.id}</td>
                                        <td>{item.alert_type}</td>
                                        <td>{item.client_ip}</td>
                                        <td>
                                            <span className={`severity ${item.severity.toLowerCase()}`}>
                                                {item.severity}
                                            </span>
                                        </td>

                                        <td>{item.status}</td>

                                        <td>

                                            {item.status === "OPEN" && (
                                                <button
                                                    onClick={() => updateIncident(item.id, "ACKNOWLEDGED")}
                                                >
                                                    Acknowledge
                                                </button>
                                            )}

                                            {item.status === "ACKNOWLEDGED" && (
                                                <button
                                                    onClick={() => updateIncident(item.id, "RESOLVED")}
                                                >
                                                    Resolve
                                                </button>
                                            )}

                                        </td>

                                    </tr>

                                ))}

                            </tbody>

                        </table>

                    </div>

                )}

            </div>

        </section>
    );
}

export default SecurityPanel;