
# IntelliDNS 🔐

### Intelligent DNS Security and Threat Intelligence Platform

IntelliDNS is an intelligent DNS security platform designed to monitor DNS queries, detect suspicious domains, identify potential DNS-based attacks, and block known malicious destinations using threat intelligence.

The platform combines a custom DNS engine, STIX-based threat intelligence, advanced security detection, monitoring APIs, and a React dashboard to provide centralized DNS security monitoring.

---

## 🚀 Key Features

### 1. DNS Core

- DNS query handling over UDP.
- Domain resolution and response processing.
- DNS response caching with TTL management.
- DNS query logging and error handling.
- DNS response validation.

### 2. Threat Intelligence

- Local domain blacklist.
- STIX threat intelligence feed integration.
- Automatic extraction of malicious domain indicators.
- Detection of known malicious and phishing domains.
- Blocking of matching malicious domains.

### 3. Advanced Security

- Rate limiting for DNS clients.
- Suspicious domain analysis.
- DGA-like domain detection using heuristic analysis.
- DNS tunneling detection.
- Anomaly detection and behavioral analysis.
- IP blocking and automatic expiry.
- Risk scoring and severity classification.

### 4. Monitoring and Analytics

- DNS threat event storage.
- Threat event history.
- Severity-based threat statistics.
- Threat category analysis.
- Top suspicious domains and clients.
- Threat health monitoring.
- API-based analytics.

### 5. Web Dashboard

- React-based monitoring dashboard.
- Security monitoring panels.
- Threat analytics and event visualization.
- Backend API integration.
- Nginx reverse proxy for API requests.

### 6. Docker Deployment

- Containerized DNS service.
- Containerized FastAPI backend.
- Containerized React dashboard.
- Docker Compose orchestration.
- Persistent SQLite database and log storage.

---

## 🛠️ Technology Stack

| Component           | Technology                                             |
| ------------------- | ------------------------------------------------------ |
| DNS Engine          | Python, dnslib                                         |
| Backend             | FastAPI                                                |
| Frontend            | React, Vite                                            |
| Web Server          | Nginx                                                  |
| Database            | SQLite                                                 |
| Threat Intelligence | STIX                                                   |
| Security            | Rate Limiting, DGA Heuristics, DNS Tunneling Detection |
| Containerization    | Docker, Docker Compose                                 |
| Testing             | Python unittest                                        |

---

## 📁 Project Structure

```text
IntelliDNS/
│
├── api/
│   └── server.py
│
├── dashboard/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── App.css
│   │   ├── SecurityPanel.jsx
│   │   ├── SecurityPanel.css
│   │   ├── ThreatPanel.jsx
│   │   └── ThreatPanel.css
│   ├── Dockerfile
│   └── nginx.conf
│
├── dns_engine/
│   ├── cache.py
│   ├── query_handler.py
│   ├── resolver.py
│   └── resolver_backup.py
│
├── monitoring/
│   ├── analytics.py
│   ├── database.py
│   └── threat_store.py
│
├── security/
│   ├── alert_manager.py
│   ├── anomaly_detector.py
│   ├── advanced_detector.py
│   ├── domain_analyzer.py
│   ├── ip_blocklist.py
│   ├── rate_limiter.py
│   ├── response_engine.py
│   ├── response_manager.py
│   └── tunneling_detector.py
│
├── tests/
│   ├── test_client.py
│   ├── test_dns_integration.py
│   ├── test_phase5.py
│   ├── test_response.py
│   ├── test_security.py
│   └── test_cache.py
│
├── threat_intelligence/
│   ├── feeds/
│   │   └── local_stix_bundle.json
│   ├── blacklist.py
│   └── stix_feed.py
│
├── logs/                  # Created at runtime
├── main.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
└── .gitignore
```

---

## ⚙️ Local Installation and Setup

### Prerequisites

- Python 3.10+
- Node.js and npm
- Git

### 1. Clone the repository

```bash
git clone https://github.com/tiwaripallavii0018/IntelliDNS.git
cd IntelliDNS
```

### 2. Create a virtual environment

Windows PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

### 4. Start the DNS server

```powershell
python main.py
```

The DNS server listens on UDP port `5353` by default.

### 5. Start the backend API

Open another terminal:

```powershell
.\venv\Scripts\Activate.ps1
uvicorn api.server:app --host 127.0.0.1 --port 8000
```

API documentation:

http://localhost:8000/docs

### 6. Start the dashboard

Open another terminal:

```powershell
cd dashboard
npm install
npm run dev
```

Dashboard:

http://localhost:5173

---

## 🐳 Docker Deployment

### Prerequisites

- Docker Desktop
- Docker Compose

### 1. Clone the repository

```powershell
git clone https://github.com/tiwaripallavii0018/IntelliDNS.git
cd IntelliDNS
```

### 2. Initialize the database

The SQLite database is excluded from Git to avoid committing local runtime data.

Create it only if it does not already exist:

```powershell
if (!(Test-Path .\intellidns.db)) {
    New-Item -ItemType File .\intellidns.db | Out-Null
}
```

This preserves an existing database and creates a new empty file for fresh installations.

### 3. Build and start containers

```powershell
docker compose up --build -d
```

### 4. Check container status

```powershell
docker compose ps
```

### 5. Access the services

| Service           | Address                    |
| ----------------- | -------------------------- |
| Web Dashboard     | http://localhost:8080      |
| Backend API       | http://localhost:8000      |
| API Documentation | http://localhost:8000/docs |
| DNS Server        | localhost:5354 (UDP)       |

**Docker DNS port mapping:** Host UDP port `5354` maps to container UDP port `5353`. This avoids conflicts with applications already using the host DNS port.

The dashboard communicates with the backend through the Nginx reverse proxy.

### 6. View container logs

```powershell
docker compose logs -f
```

Individual services:

```powershell
docker compose logs -f dns
docker compose logs -f api
docker compose logs -f dashboard
```

### 7. Stop containers

```powershell
docker compose down
```

The database file is mounted from the host and is not removed by this command.

---

## 🧪 Testing

Run the tests from the project root with the virtual environment activated:

```powershell
python -m tests.test_cache
python -m tests.test_security
python -m tests.test_response
python -m tests.test_phase5
python -m tests.test_client
python -m tests.test_dns_integration
```

### Test Coverage

- DNS cache hit and miss.
- Cache size and TTL expiry.
- DNS transaction ID handling.
- NXDOMAIN caching behavior.
- Rate limiting.
- Domain analysis.
- DNS tunneling detection.
- Anomaly detection.
- IP blocking and unblocking.
- Automatic IP block expiry.
- DNS client and integration behavior.

### Frontend Production Build

```powershell
cd dashboard
npm install
npm run build
```

---

## 🔌 Backend API Endpoints

| Endpoint                  | Description                     |
| ------------------------- | ------------------------------- |
| `/api/threat-events`    | Retrieves recent threat events  |
| `/api/threat-analytics` | Provides threat analytics       |
| `/api/threat-health`    | Checks threat monitoring health |

Interactive API documentation:

http://localhost:8000/docs

---

## 🔍 Threat Detection Workflow

1. A client sends a DNS query.
2. IntelliDNS receives and processes the request.
3. Rate limiting checks the client's request frequency.
4. The requested domain is checked against local and STIX-based threat intelligence.
5. Advanced security modules analyze suspicious domain patterns and behavior.
6. A risk score and severity level are assigned.
7. Malicious requests can be blocked with an NXDOMAIN response.
8. Threat events are stored for monitoring and analytics.
9. The dashboard displays security activity.

---

## 📊 Security and Limitations

- DGA detection currently uses heuristic analysis, not a trained machine-learning classifier.
- The local STIX bundle is provided for demonstration and testing.
- Detection results depend on configured threat feeds and detection thresholds.
- SQLite is used for project-level persistence.
- This platform is intended for educational, research, and demonstration purposes and is not a replacement for production-grade enterprise DNS infrastructure.

---

## 🔮 Future Enhancements

- Integration with additional live threat intelligence feeds.
- Improved threat confidence scoring.
- Persistent behavioral analytics.
- Enhanced DNS anomaly detection.
- Advanced dashboard visualizations.
- Authentication and role-based access control.
- Production-grade deployment and scalability improvements.

---

## 👩‍💻 Contributors

Developed as a cybersecurity project focused on intelligent DNS monitoring, threat detection, and threat intelligence integration.

---

## 📄 License

This project is intended for educational, research, and demonstration purposes.
