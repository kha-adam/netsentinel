# NetSentinel

A lightweight Network Security Monitoring and Intrusion Detection System built with Python and Scapy.

NetSentinel monitors network traffic, tracks TCP connections, detects suspicious network behavior, stores security alerts in SQLite, and provides a web dashboard for monitoring detected threats.

## Features

* Real-time packet capture with **Scapy**
* TCP connection state tracking
* **Port scan detection**
* **SYN flood detection**
* **SSH brute-force detection**
* SSH authentication log parsing
* Persistent alert storage with **SQLite**
* REST API for retrieving alerts
* Web dashboard built with **Flask**
* Automated testing with **pytest**

## Architecture

```text
                         ┌─────────────────────┐
                         │    Network Traffic  │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   Scapy Sniffer     │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ Connection Tracker  │
                         │   TCP State Machine │
                         └──────────┬──────────┘
                                    │
                       ┌────────────┼────────────┐
                       ▼            ▼            ▼
                ┌────────────┐ ┌───────────┐ ┌──────────────┐
                │ Port Scan  │ │ SYN Flood │ │ SSH Brute    │
                │ Detector   │ │ Detector  │ │ Force        │
                └─────┬──────┘ └─────┬─────┘ └──────┬───────┘
                      │              │               │
                      └──────────────┼───────────────┘
                                     ▼
                            ┌─────────────────┐
                            │  Alert Manager  │
                            └────────┬────────┘
                                     │
                                     ▼
                            ┌─────────────────┐
                            │     SQLite      │
                            └────────┬────────┘
                                     │
                                     ▼
                            ┌─────────────────┐
                            │ Flask Dashboard │
                            └─────────────────┘
```

SSH authentication events follow a separate path:

```text
SSH Authentication Logs
          │
          ▼
    SSH Log Reader
          │
          ▼
 SSH_AUTH_FAILURE events
          │
          ▼
 SSH Brute-Force Detector
          │
          ▼
    Alert Manager
```

## Detection Methods

### Port Scan Detection

NetSentinel tracks TCP SYN packets originating from each source IP.

A port scan is detected when a source attempts connections to a configurable number of distinct destination ports within a defined time window.

Example:

```text
192.168.1.50 → port 21
192.168.1.50 → port 22
192.168.1.50 → port 23
192.168.1.50 → port 80
192.168.1.50 → port 443
```

A large number of distinct destination ports within a short period can indicate reconnaissance activity.

### SYN Flood Detection

NetSentinel monitors both:

* the rate of incoming TCP SYN packets
* the number of incomplete TCP connections

An alert is generated when both measurements exceed configurable thresholds.

This helps distinguish a potentially malicious SYN flood from legitimate bursts of connection attempts.

### SSH Brute-Force Detection

SSH authentication failures are read from system logs and converted into normalized events.

Repeated authentication failures from the same source within a configurable time window trigger an SSH brute-force alert.

Because SSH authentication is encrypted, the detector relies on host-level authentication logs rather than attempting to infer password failures from network packets.

## Technologies

| Technology | Purpose                                    |
| ---------- | ------------------------------------------ |
| Python     | Core implementation                        |
| Scapy      | Packet capture and network packet analysis |
| SQLite     | Alert storage                              |
| Flask      | Web dashboard and REST API                 |
| pytest     | Automated testing                          |
| Git        | Version control                            |

## Project Structure

```text
netsentinel/
├── src/
│   └── netsentinel/
│       ├── __init__.py
│       ├── sniffer.py
│       ├── connection_tracker.py
│       ├── alert_manager.py
│       ├── log_reader.py
│       ├── database.py
│       ├── app.py
│       └── detectors/
│           ├── __init__.py
│           ├── port_scan.py
│           ├── syn_flood.py
│           └── ssh_bruteforce.py
├── tests/
├── docs/
├── .gitignore
├── README.md
└── requirements.txt
```

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/netsentinel.git
cd netsentinel
```

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Running NetSentinel

Packet capture generally requires elevated privileges.

Run the network monitor:

```bash
sudo python src/netsentinel/sniffer.py
```

The Flask dashboard can be started separately:

```bash
python src/netsentinel/app.py
```

Then open:

```text
http://127.0.0.1:5000
```

The dashboard displays detected alerts and periodically refreshes its data through the REST API.

## API

### Get alerts

```http
GET /api/alerts
```

Example response:

```json
[
  {
    "id": 22,
    "timestamp": 1757580000,
    "type": "PORT_SCAN",
    "source": "192.168.1.50",
    "severity": "HIGH",
    "details": {
      "ports": [21, 22, 80, 443],
      "timeframe": 5
    }
  }
]
```

## Testing

NetSentinel includes automated tests covering the main components of the system.

Run the test suite with:

```bash
pytest
```

The tests cover:

* Port scan detection
* SYN flood detection
* SSH brute-force detection
* SSH log parsing
* TCP connection tracking
* SQLite database operations
* Flask API
* Dashboard rendering
* Detection pipeline integration

## Design Decisions

### SQLite

SQLite was chosen because NetSentinel is designed as a lightweight, single-node monitoring application. It requires no database server and provides sufficient persistence for the current architecture.

A server-based database such as PostgreSQL could be considered for a multi-agent deployment or a system handling significantly higher write concurrency.

### Direction-independent TCP connections

TCP connections are represented using both endpoints rather than simply the packet source and destination.

```text
(client IP, client port)
        ↕
(server IP, server port)
```

This allows packets belonging to the same connection to be associated even when their direction changes.

### Detector separation

Each detection mechanism is implemented independently.

```text
Packet/Event
     ↓
Detector
     ↓
Alert
```

This allows individual detection strategies to be tested and modified without coupling them to packet capture, storage, or the dashboard.

## Limitations

NetSentinel is an educational and experimental security monitoring project rather than a production IDS.

Current limitations include:

* Detection thresholds are manually configured.
* Port-scan detection can produce false positives from legitimate applications.
* SYN-flood detection is based on behavioral thresholds rather than a complete traffic baseline.
* SSH brute-force detection depends on the availability and format of system authentication logs.
* The current architecture is designed for a single monitoring node.
* macOS and Linux expose system logs differently, so SSH log collection is platform-dependent.
* No machine-learning-based anomaly detection is currently implemented.

## Future Improvements

Potential future improvements include:

* Configurable detection thresholds
* Improved TCP state validation
* Additional network attack detectors
* Alert filtering and search
* Historical traffic visualizations
* Better log rotation handling
* Docker deployment
* Multi-host monitoring
* Anomaly detection using machine learning

## Disclaimer

NetSentinel is intended for **educational and authorized security testing purposes only**.

Only monitor networks and systems that you own or have explicit permission to analyze.

