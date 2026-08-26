# NetSentry

A Python-based network traffic monitoring and intrusion detection system (IDS), built from scratch — packet capture, signature-based rule engine, and a live web dashboard.

## Why this project

Most IDS/SIEM tools are black boxes you learn to *operate*. NetSentry is an attempt to understand what's happening *inside* one — capturing raw traffic, matching it against detection rules, and surfacing alerts in real time — the same core loop that tools like Snort, Suricata, and Splunk are built on.

## Architecture

```
┌─────────────┐      ┌──────────────┐      ┌───────────────┐
│   Sniffer    │ ──▶  │   SQLite DB   │ ◀──  │  Rule Engine   │
│  (Scapy)     │      │  (packets +   │      │ (rules.json)   │
└─────────────┘      │   alerts)     │      └───────────────┘
                       └──────┬───────┘
                              │
                       ┌──────▼───────┐
                       │  Dashboard    │
                       │ (Streamlit)   │
                       └──────────────┘
```

The sniffer and dashboard are decoupled — they only communicate through the database. This means the detection engine can run headless (e.g., on a home network) while the dashboard is deployed separately (e.g., on AWS) for review.

## Tech stack

| Layer | Tool |
|---|---|
| Packet capture | Scapy |
| Capture driver | Npcap (Windows) / libpcap (Linux/Mac) |
| Storage | SQLite |
| Rule engine | Python + JSON rule definitions |
| Dashboard | Streamlit |
| Testing traffic | nmap, hping3 |

## Status

🚧 Early development — see [Roadmap](#roadmap) below.

## Getting started

```bash
https://github.com/Sarthak77sec/NetSentry.git
cd NetSentry
pip install -r requirements.txt

# Packet capture needs elevated privileges
sudo python3 main.py          # Linux/Mac
# or run as Administrator on Windows
```

## Project structure

```
netsentry/
├── config/
│   └── rules.json          # Signature-based detection rules
├── core/
│   ├── sniffer.py          # Live packet capture (Scapy)
│   ├── db.py                # SQLite schema + helpers
│   ├── rule_engine.py       # Loads rules, evaluates traffic
│   └── models.py            # Data classes for Packet/Alert
├── dashboard/
│   └── app.py                # Streamlit dashboard
├── data/
│   └── netsentry.db          # SQLite DB (gitignored)
├── tests/
│   ├── test_rule_engine.py
│   └── generate_test_traffic.py
└── main.py                    # Entry point
```

## Roadmap

- [x] Project scaffolding
- [ ] Live packet sniffer (Scapy)
- [ ] SQLite logging
- [ ] Signature-based rule engine (port scan, ICMP flood, malicious ports)
- [ ] Alerting
- [ ] Streamlit dashboard
- [ ] Test traffic generation + validation
- [ ] Dockerize
- [ ] Deploy demo to AWS

## Detection approach

NetSentry starts with **signature-based detection** — matching traffic against known-bad patterns (port scans, ICMP floods, connections to known malicious ports), the same approach used by Snort/Suricata. Anomaly-based detection (statistical baselining) is a planned stretch goal.

## Disclaimer

Built and tested only against traffic on networks/devices I own or have explicit permission to monitor. Not intended for use on networks without authorization.

## Author

Sarthak Sharma
