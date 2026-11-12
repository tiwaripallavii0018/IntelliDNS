
import { useEffect, useState } from "react";
import {
    LayoutDashboard,
    Activity,
    ShieldAlert,
    ShieldCheck,
    Bell,
    Globe,
    Menu,
    X,
    RefreshCw,
    Search,
    Server,
    CircleAlert,
    ChevronRight
} from "lucide-react";

import ThreatPanel from "./ThreatPanel";
import SecurityPanel from "./SecurityPanel";
import "./App.css";

const API = import.meta.env.VITE_API_URL ?? "http://127.0.0.1:8000";

const navigation = [
    { id: "overview", label: "Overview", icon: LayoutDashboard },
    { id: "traffic", label: "DNS Traffic", icon: Activity },
    { id: "threats", label: "Threat Intelligence", icon: ShieldAlert },
    { id: "security", label: "Security Response", icon: ShieldCheck },
    { id: "alerts", label: "Security Alerts", icon: Bell },
    { id: "domains", label: "Domain Analytics", icon: Globe }
];

function StatCard({ title, value, subtitle, icon: Icon, color }) {
    return (
        <div className="stat-card">
            <div className={`stat-icon ${color}`}>
                <Icon size={21} />
            </div>

            <div className="stat-content">
                <p>{title}</p>
                <h2>{value ?? 0}</h2>
                {subtitle && <span>{subtitle}</span>}
            </div>
        </div>
    );
}

function EmptyState({ message }) {
    return (
        <div className="empty-state">
            <Search size={25} />
            <p>{message}</p>
        </div>
    );
}

function formatTime(value) {
    if (!value) return "N/A";

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) return String(value);

    return date.toLocaleString();
}

function OverviewPage({ stats, queries, alerts, domains, securityStats }) {
    const totalQueries =
        stats.total_queries ??
        stats.total ??
        stats.query_count ??
        0;

    const blockedQueries =
        stats.blocked_queries ??
        stats.blocked ??
        securityStats.blocked_queries ??
        0;

    const suspiciousQueries =
        stats.suspicious_queries ??
        stats.suspicious ??
        0;

    const cacheHits =
        stats.cache_hits ??
        stats.cache_hit ??
        0;

    return (
        <div className="page-content">
            <div className="welcome-section">
                <div>
                    <span className="eyebrow">NETWORK SECURITY DASHBOARD</span>
                    <h1>Dashboard Overview</h1>
                    <p>
                        Monitor DNS activity, identify threats and manage
                        network security from one place.
                    </p>
                </div>

                <div className="live-indicator">
                    <span className="live-dot"></span>
                    Live monitoring
                </div>
            </div>

            <div className="stats-grid">
                <StatCard
                    title="Total DNS Queries"
                    value={totalQueries}
                    subtitle="Total recorded queries"
                    icon={Activity}
                    color="blue"
                />

                <StatCard
                    title="Blocked Queries"
                    value={blockedQueries}
                    subtitle="Queries blocked by security rules"
                    icon={ShieldAlert}
                    color="red"
                />

                <StatCard
                    title="Suspicious Queries"
                    value={suspiciousQueries}
                    subtitle="Potentially malicious activity"
                    icon={CircleAlert}
                    color="orange"
                />

                <StatCard
                    title="Cache Hits"
                    value={cacheHits}
                    subtitle="Queries served from cache"
                    icon={Server}
                    color="green"
                />
            </div>

            <div className="overview-grid">
                <section className="content-card overview-table-card">
                    <div className="section-heading">
                        <div>
                            <h3>Recent DNS Queries</h3>
                            <p>Latest network activity</p>
                        </div>
                    </div>

                    {queries.length === 0 ? (
                        <EmptyState message="No DNS queries recorded yet." />
                    ) : (
                        <div className="table-wrapper">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Domain</th>
                                        <th>Client IP</th>
                                        <th>Status</th>
                                        <th>Time</th>
                                    </tr>
                                </thead>

                                <tbody>
                                    {queries.slice(0, 7).map((item, index) => (
                                        <tr key={item.id ?? index}>
                                            <td className="domain-cell">
                                                {item.domain ?? item.qname ?? "N/A"}
                                            </td>
                                            <td>{item.client_ip ?? item.ip ?? "N/A"}</td>
                                            <td>
                                                <span className={`status-badge ${String(
                                                    item.status ?? item.action ?? "allowed"
                                                ).toLowerCase()}`}>
                                                    {item.status ?? item.action ?? "Allowed"}
                                                </span>
                                            </td>
                                            <td>{formatTime(item.timestamp ?? item.time)}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </section>

                <section className="content-card overview-side-card">
                    <div className="section-heading">
                        <div>
                            <h3>Top Domains</h3>
                            <p>Most frequently requested</p>
                        </div>
                    </div>

                    {domains.length === 0 ? (
                        <EmptyState message="No domain data available." />
                    ) : (
                        <div className="domain-list">
                            {domains.slice(0, 6).map((item, index) => (
                                <div className="domain-item" key={item.domain ?? index}>
                                    <div className="domain-rank">{index + 1}</div>
                                    <div className="domain-info">
                                        <strong>{item.domain ?? "Unknown"}</strong>
                                        <span>{item.count ?? item.queries ?? 0} queries</span>
                                    </div>
                                    <ChevronRight size={17} />
                                </div>
                            ))}
                        </div>
                    )}
                </section>
            </div>

            <section className="content-card">
                <div className="section-heading">
                    <div>
                        <h3>Recent Security Alerts</h3>
                        <p>Latest detected security events</p>
                    </div>
                </div>

                {alerts.length === 0 ? (
                    <EmptyState message="No security alerts recorded." />
                ) : (
                    <div className="alert-list">
                        {alerts.slice(0, 5).map((alert, index) => (
                            <div className="alert-item" key={alert.id ?? index}>
                                <div className="alert-symbol">
                                    <ShieldAlert size={18} />
                                </div>
                                <div className="alert-info">
                                    <strong>
                                        {alert.alert_type ?? alert.type ?? "Security Alert"}
                                    </strong>
                                    <span>
                                        {alert.domain ?? alert.client_ip ?? "Unknown source"}
                                    </span>
                                </div>
                                <span className={`severity-badge ${String(
                                    alert.severity ?? "low"
                                ).toLowerCase()}`}>
                                    {alert.severity ?? "LOW"}
                                </span>
                            </div>
                        ))}
                    </div>
                )}
            </section>
        </div>
    );
}

function TrafficPage({ queries }) {
    return (
        <div className="page-content">
            <div className="page-heading">
                <span className="eyebrow">NETWORK ACTIVITY</span>
                <h1>DNS Traffic</h1>
                <p>Inspect DNS requests flowing through your resolver.</p>
            </div>

            <section className="content-card">
                <div className="section-heading">
                    <div>
                        <h3>DNS Query Logs</h3>
                        <p>{queries.length} records currently loaded</p>
                    </div>
                </div>

                {queries.length === 0 ? (
                    <EmptyState message="No DNS traffic available yet." />
                ) : (
                    <div className="table-wrapper">
                        <table>
                            <thead>
                                <tr>
                                    <th>Domain</th>
                                    <th>Client IP</th>
                                    <th>Query Type</th>
                                    <th>Status</th>
                                    <th>Response</th>
                                    <th>Timestamp</th>
                                </tr>
                            </thead>

                            <tbody>
                                {queries.map((item, index) => (
                                    <tr key={item.id ?? index}>
                                        <td className="domain-cell">
                                            {item.domain ?? item.qname ?? "N/A"}
                                        </td>
                                        <td>{item.client_ip ?? item.ip ?? "N/A"}</td>
                                        <td>{item.query_type ?? item.qtype ?? "A"}</td>
                                        <td>
                                            <span className={`status-badge ${String(
                                                item.status ?? item.action ?? "allowed"
                                            ).toLowerCase()}`}>
                                                {item.status ?? item.action ?? "Allowed"}
                                            </span>
                                        </td>
                                        <td>{item.response ?? item.answer ?? "N/A"}</td>
                                        <td>{formatTime(item.timestamp ?? item.time)}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </section>
        </div>
    );
}

function AlertsPage({ alerts }) {
    return (
        <div className="page-content">
            <div className="page-heading">
                <span className="eyebrow">THREAT NOTIFICATIONS</span>
                <h1>Security Alerts</h1>
                <p>Review security alerts generated by IntelliDNS.</p>
            </div>

            <section className="content-card">
                <div className="section-heading">
                    <div>
                        <h3>All Security Alerts</h3>
                        <p>{alerts.length} alerts loaded</p>
                    </div>
                </div>

                {alerts.length === 0 ? (
                    <EmptyState message="No security alerts available." />
                ) : (
                    <div className="table-wrapper">
                        <table>
                            <thead>
                                <tr>
                                    <th>Alert Type</th>
                                    <th>Domain</th>
                                    <th>Client IP</th>
                                    <th>Severity</th>
                                    <th>Timestamp</th>
                                </tr>
                            </thead>

                            <tbody>
                                {alerts.map((item, index) => (
                                    <tr key={item.id ?? index}>
                                        <td>{item.alert_type ?? item.type ?? "N/A"}</td>
                                        <td>{item.domain ?? "N/A"}</td>
                                        <td>{item.client_ip ?? "N/A"}</td>
                                        <td>
                                            <span className={`severity-badge ${String(
                                                item.severity ?? "low"
                                            ).toLowerCase()}`}>
                                                {item.severity ?? "LOW"}
                                            </span>
                                        </td>
                                        <td>{formatTime(item.timestamp ?? item.time)}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </section>
        </div>
    );
}

function DomainsPage({ domains }) {
    return (
        <div className="page-content">
            <div className="page-heading">
                <span className="eyebrow">DNS INSIGHTS</span>
                <h1>Domain Analytics</h1>
                <p>Understand which domains are being requested most often.</p>
            </div>

            <section className="content-card">
                <div className="section-heading">
                    <div>
                        <h3>Top Queried Domains</h3>
                        <p>Domain request distribution</p>
                    </div>
                </div>

                {domains.length === 0 ? (
                    <EmptyState message="No domain analytics available." />
                ) : (
                    <div className="table-wrapper">
                        <table>
                            <thead>
                                <tr>
                                    <th>Rank</th>
                                    <th>Domain</th>
                                    <th>Total Queries</th>
                                    <th>Blocked Queries</th>
                                </tr>
                            </thead>

                            <tbody>
                                {domains.map((item, index) => (
                                    <tr key={item.domain ?? index}>
                                        <td>{index + 1}</td>
                                        <td className="domain-cell">{item.domain ?? "N/A"}</td>
                                        <td>{item.count ?? item.queries ?? 0}</td>
                                        <td>{item.blocked ?? item.blocked_count ?? 0}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </section>
        </div>
    );
}

function App() {
    const [activePage, setActivePage] = useState("overview");
    const [sidebarOpen, setSidebarOpen] = useState(false);

    const [stats, setStats] = useState({});
    const [queries, setQueries] = useState([]);
    const [domains, setDomains] = useState([]);
    const [alerts, setAlerts] = useState([]);
    const [securityStats, setSecurityStats] = useState({});

    const [loading, setLoading] = useState(true);
    const [apiError, setApiError] = useState("");

    async function loadDashboardData() {
        try {
            const endpoints = [
                "/api/stats",
                "/api/queries",
                "/api/top-domains",
                "/api/alerts",
                "/api/security-stats"
            ];

            const responses = await Promise.all(
                endpoints.map(endpoint => fetch(`${API}${endpoint}`))
            );

            const failedResponse = responses.find(response => !response.ok);

            if (failedResponse) {
                throw new Error(`Dashboard API error: ${failedResponse.status}`);
            }

            const [
                statsData,
                queryData,
                domainData,
                alertData,
                securityData
            ] = await Promise.all(responses.map(response => response.json()));

            setStats(statsData ?? {});
            setQueries(Array.isArray(queryData) ? queryData : queryData.queries ?? []);
            setDomains(Array.isArray(domainData) ? domainData : domainData.domains ?? []);
            setAlerts(Array.isArray(alertData) ? alertData : alertData.alerts ?? []);
            setSecurityStats(securityData ?? {});

            setApiError("");
        } catch (error) {
            setApiError(error.message || "Unable to connect to the backend.");
        } finally {
            setLoading(false);
        }
    }

    useEffect(() => {
        loadDashboardData();

        const timer = setInterval(loadDashboardData, 5000);

        return () => clearInterval(timer);
    }, []);

    const currentPage = navigation.find(item => item.id === activePage);
    const ActiveIcon = currentPage?.icon ?? LayoutDashboard;

    function changePage(page) {
        setActivePage(page);
        setSidebarOpen(false);
    }

    function renderPage() {
        switch (activePage) {
            case "traffic":
                return <TrafficPage queries={queries} />;

            case "threats":
                return <ThreatPanel />;

            case "security":
                return <SecurityPanel />;

            case "alerts":
                return <AlertsPage alerts={alerts} />;

            case "domains":
                return <DomainsPage domains={domains} />;

            default:
                return (
                    <OverviewPage
                        stats={stats}
                        queries={queries}
                        alerts={alerts}
                        domains={domains}
                        securityStats={securityStats}
                    />
                );
        }
    }

    return (
        <div className="app-shell">
            {sidebarOpen && (
                <div
                    className="sidebar-overlay"
                    onClick={() => setSidebarOpen(false)}
                />
            )}

            <aside className={`sidebar ${sidebarOpen ? "sidebar-open" : ""}`}>
                <div className="brand">
                    <div className="brand-logo">
                        <ShieldCheck size={25} />
                    </div>

                    <div>
                        <h2>IntelliDNS</h2>
                        <span>DNS Security Platform</span>
                    </div>

                    <button
                        className="mobile-close"
                        onClick={() => setSidebarOpen(false)}
                        aria-label="Close menu"
                    >
                        <X size={20} />
                    </button>
                </div>

                <div className="sidebar-label">WORKSPACE</div>

                <nav className="sidebar-nav">
                    {navigation.map(item => {
                        const Icon = item.icon;

                        return (
                            <button
                                key={item.id}
                                className={`nav-item ${
                                    activePage === item.id ? "active" : ""
                                }`}
                                onClick={() => changePage(item.id)}
                            >
                                <Icon size={19} />
                                <span>{item.label}</span>
                            </button>
                        );
                    })}
                </nav>

                <div className="sidebar-bottom">
                    <div className="system-status">
                        <span className="live-dot"></span>
                        <div>
                            <strong>System monitoring</strong>
                            <span>Automatic refresh enabled</span>
                        </div>
                    </div>

                    <div className="sidebar-version">
                        IntelliDNS · Security Console
                    </div>
                </div>
            </aside>

            <main className="main-area">
                <header className="topbar">
                    <div className="topbar-left">
                        <button
                            className="menu-button"
                            onClick={() => setSidebarOpen(true)}
                            aria-label="Open menu"
                        >
                            <Menu size={22} />
                        </button>

                        <div className="breadcrumb">
                            <span>Workspace</span>
                            <ChevronRight size={15} />
                            <strong>{currentPage?.label ?? "Overview"}</strong>
                        </div>
                    </div>

                    <div className="topbar-right">
                        <div className="topbar-status">
                            <span className="live-dot"></span>
                            Live
                        </div>

                        <button
                            className="refresh-button"
                            onClick={loadDashboardData}
                            title="Refresh dashboard"
                        >
                            <RefreshCw size={17} />
                            <span>Refresh</span>
                        </button>
                    </div>
                </header>

                {apiError && (
                    <div className="api-error">
                        <CircleAlert size={18} />
                        <span>{apiError}</span>
                    </div>
                )}

                {loading ? (
                    <div className="loading-state">
                        <RefreshCw className="loading-icon" size={27} />
                        <p>Loading IntelliDNS dashboard...</p>
                    </div>
                ) : (
                    <div className="workspace-content">
                        <div className="active-page-heading">
                            <div className="active-page-icon">
                                <ActiveIcon size={19} />
                            </div>
                            <span>{currentPage?.label ?? "Overview"}</span>
                        </div>

                        {renderPage()}
                    </div>
                )}

                <footer className="app-footer">
                    <span>IntelliDNS</span>
                    <span>DNS Security & Threat Intelligence</span>
                </footer>
            </main>
        </div>
    );
}

export default App;
