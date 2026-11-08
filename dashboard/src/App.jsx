import { useEffect, useState } from "react";

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer
} from "recharts";

import {
  ShieldCheck,
  ShieldAlert,
  Activity,
  Globe,
  AlertTriangle,
  RefreshCw,
  Clock
} from "lucide-react";

import "./App.css";

const API = "http://127.0.0.1:8000";

function App() {

  const [stats, setStats] = useState({});
  const [queries, setQueries] = useState([]);
  const [domains, setDomains] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [securityStats, setSecurityStats] = useState({});
  const [lastUpdated, setLastUpdated] = useState("");

  async function loadData() {

    try {

      const [
        statsRes,
        queriesRes,
        domainsRes,
        alertsRes,
        securityRes
      ] = await Promise.all([
        fetch(`${API}/api/stats`),
        fetch(`${API}/api/queries`),
        fetch(`${API}/api/top-domains`),
        fetch(`${API}/api/alerts`),
        fetch(`${API}/api/security-stats`)
      ]);

      if (
        !statsRes.ok ||
        !queriesRes.ok ||
        !domainsRes.ok ||
        !alertsRes.ok ||
        !securityRes.ok
      ) {
        throw new Error("One or more API requests failed");
      }

      setStats(await statsRes.json());
      setQueries(await queriesRes.json());
      setDomains(await domainsRes.json());
      setAlerts(await alertsRes.json());
      setSecurityStats(await securityRes.json());

      setLastUpdated(new Date().toLocaleTimeString());

    } catch (error) {

      console.error("Dashboard API error:", error);

    }
  }

  useEffect(() => {

    loadData();

    const interval = setInterval(loadData, 3000);

    return () => clearInterval(interval);

  }, []);

  const cards = [
    {
      title: "Total Queries",
      value: stats.total_queries || 0,
      icon: <Activity />
    },
    {
      title: "Allowed Queries",
      value: stats.allowed_queries || 0,
      icon: <ShieldCheck />
    },
    {
      title: "Blocked Queries",
      value: stats.blocked_queries || 0,
      icon: <ShieldAlert />
    },
    {
      title: "Avg Response Time",
      value: `${stats.average_response_time || 0} ms`,
      icon: <Globe />
    }
  ];

  const alertCounts = {
    HIGH: securityStats.HIGH || 0,
    MEDIUM: securityStats.MEDIUM || 0,
    LOW: securityStats.LOW || 0
  };

  function formatTime(value) {

    if (!value) {
      return "N/A";
    }

    return new Date(value).toLocaleString();

  }

  return (

    <div className="dashboard">

      <header className="topbar">

        <div className="brand">

          <div className="brand-icon">
            <ShieldCheck size={25} />
          </div>

          <div>
            <h1>IntelliDNS</h1>
            <p>DNS Security Monitoring Platform</p>
          </div>

        </div>

        <div className="header-right">

          <span className="online">
            <span className="online-dot"></span>
            Monitoring
          </span>

          <button
            className="refresh-button"
            onClick={loadData}
            title="Refresh dashboard"
          >
            <RefreshCw size={16} />
            Refresh
          </button>

        </div>

      </header>


      <main>

        <section className="section-heading">

          <div>
            <h2>Network Overview</h2>
            <p>Live DNS traffic and security monitoring</p>
          </div>

          <span className="updated">
            <Clock size={14} />
            Updated: {lastUpdated || "Loading..."}
          </span>

        </section>


        <section className="cards">

          {cards.map((card) => (

            <div className="card" key={card.title}>

              <div className="card-icon">
                {card.icon}
              </div>

              <p>{card.title}</p>
              <h2>{card.value}</h2>

            </div>

          ))}

        </section>


        <section className="section-heading security-heading">

          <div>
            <h2>Security Overview</h2>
            <p>Threat detection and security alerts</p>
          </div>

          <div className="alert-total">
            <ShieldAlert size={17} />
            {alerts.length} Recent Alerts
          </div>

        </section>


        <section className="security-cards">

          <div className="security-card high-card">

            <div className="security-icon">
              <ShieldAlert />
            </div>

            <div>
              <p>High Severity</p>
              <h2>{alertCounts.HIGH}</h2>
            </div>

          </div>


          <div className="security-card medium-card">

            <div className="security-icon">
              <AlertTriangle />
            </div>

            <div>
              <p>Medium Severity</p>
              <h2>{alertCounts.MEDIUM}</h2>
            </div>

          </div>


          <div className="security-card low-card">

            <div className="security-icon">
              <ShieldCheck />
            </div>

            <div>
              <p>Low Severity</p>
              <h2>{alertCounts.LOW}</h2>
            </div>

          </div>

        </section>


        <section className="panel">

          <div className="panel-heading">
            <div>
              <h2>Recent Security Alerts</h2>
              <p>Suspicious activity detected by IntelliDNS</p>
            </div>

            <span className="live-label">
              LIVE
            </span>
          </div>


          {alerts.length === 0 ? (

            <div className="empty-state">

              <ShieldCheck size={35} />

              <h3>No security alerts yet</h3>

              <p>
                No suspicious DNS activity has been recorded.
                Alerts will appear here when detected.
              </p>

            </div>

          ) : (

            <div className="table-wrap">

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

                  {alerts.map((alert) => (

                    <tr key={alert.id}>

                      <td className="alert-type">
                        {alert.alert_type.replaceAll("_", " ")}
                      </td>

                      <td>{alert.domain || "N/A"}</td>

                      <td>{alert.client_ip || "N/A"}</td>

                      <td>
                        <span
                          className={`severity ${(
                            alert.severity || "LOW"
                          ).toLowerCase()}`}
                        >
                          {alert.severity || "LOW"}
                        </span>
                      </td>

                      <td>{formatTime(alert.timestamp)}</td>

                    </tr>

                  ))}

                </tbody>

              </table>

            </div>

          )}

        </section>


        <section className="panel">

          <h2>Most Queried Domains</h2>

          <div className="chart-container">

            {domains.length === 0 ? (

              <div className="empty-small">
                No domain data available yet.
              </div>

            ) : (

              <ResponsiveContainer width="100%" height={280}>

                <BarChart data={domains}>

                  <XAxis
                    dataKey="domain"
                    tick={{ fontSize: 11 }}
                    interval={0}
                  />

                  <YAxis />

                  <Tooltip />

                  <Bar
                    dataKey="count"
                    fill="#36a68a"
                    radius={[6, 6, 0, 0]}
                  />

                </BarChart>

              </ResponsiveContainer>

            )}

          </div>

        </section>


        <section className="panel">

          <h2>Recent DNS Activity</h2>

          {queries.length === 0 ? (

            <div className="empty-small">
              No DNS queries recorded yet.
            </div>

          ) : (

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

                  {queries.map((q) => (

                    <tr key={q.id}>

                      <td>{q.domain}</td>
                      <td>{q.client_ip}</td>

                      <td>
                        <span className={`status ${(
                          q.status || "ERROR"
                        ).toLowerCase()}`}>
                          {q.status}
                        </span>
                      </td>

                      <td>{q.response_time} ms</td>
                      <td>{formatTime(q.timestamp)}</td>

                    </tr>

                  ))}

                </tbody>

              </table>

            </div>

          )}

        </section>

      </main>


      <footer>
        IntelliDNS | DNS Security Monitoring Platform
      </footer>

    </div>

  );

}

export default App;