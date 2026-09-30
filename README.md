# SecureMailScope: Enterprise Cyber Threat Hunting Platform
**Smart India Hackathon 2026 | Problem Statement 26159 | NTRO**

SecureMailScope is a state-of-the-art, full-stack network forensic analysis platform designed for deep inspection of email traffic (IMAP, POP3, SMTP). Unlike traditional IDSs that rely strictly on signatures, SecureMailScope utilizes a **Hybrid Artificial Intelligence** approach combined with **Active Defense** capabilities to detect, analyze, and automatically neutralize advanced persistent threats (APTs) targeting cryptographic protocols.

## 🚀 Key Innovation: Beyond Detection to "Active Response"

Most hackathon submissions parse PCAP files and print a static table of TLS versions. SecureMailScope is a live, automated Security Operations Center (SOC) in a box:

1. **Hybrid AI Engine:** Combines a Random Forest ML algorithm trained on over 100,000 network streams with deterministic Heuristic Intelligence (JA3 TLS fingerprinting) to eliminate false positives while catching zero-day anomalies.
2. **YARA Deep Payload Inspection:** Extracts payloads directly from intercepted streams and scans raw hex data against compiled YARA rules for Cobalt Strike beacons, Ransomware signatures, and malicious PowerShell execution.
3. **Automated IPS (Intrusion Prevention System):** When a critical threat is confirmed (ML Anomaly + YARA/CTI match), the risk engine automatically interfaces with the host Operating System's firewall to instantly block the malicious IP.
4. **Live Network Sniffing:** Bypasses the need for static PCAP uploads by utilizing Promiscuous Mode (`scapy`) to intercept and analyze live network traffic straight from the NIC.
5. **Automated SOC Alerting:** Constructs high-priority incident emails and dispatches them to incident response teams seamlessly.

---

## 🧠 Architecture Overview

### 1. The React/Three.js Frontend (Dark-Mode SOC Dashboard)
- **Target Matrix & 3D Global Map:** Real-time visualization of attacker origins and threat vectors mapped globally using Three.js and custom Shaders.
- **Forensic Drill-Down:** Clicking on any compromised stream opens a modal showing raw packet data, hex dumps, and cryptographic parameters.
- **Risk Scoring:** An intuitive `0-100` scoring system where streams are categorized into SECURE, ELEVATED, HIGH, or CRITICAL based on cryptographic vulnerabilities.

### 2. The Python/FastAPI Backend
- **Stream Reconstruction:** Uses `pyshark` and `tshark` to stitch together fragmented TCP streams, pulling out raw application-layer data for inspection.
- **Cryptographic Audit:** Deep analysis of Cipher Suites, Perfect Forward Secrecy (PFS), X.509 Certificates (Self-signed, expired, weak algorithms), and TLS Version deprecations (SSLv3, TLS 1.0/1.1).
- **SQLite Persistent Storage:** Caches analyzed sessions for historical baselining and allows the generation of extensive forensic reports.
- **Export Capabilities:** Instantly generate STIX 2.1 Threat Intel bundles, Suricata IDS rules, HTML reports, and PDF incident reports.

---

## 🛠️ Tech Stack

**Frontend:**
- React 18, TypeScript, Vite
- Tailwind CSS (Utility-first styling, custom Glassmorphism UI)
- Three.js & React-Globe.gl (3D Visualization)
- Recharts (Interactive data analytics)

**Backend:**
- Python 3.12, FastAPI (Asynchronous API endpoints)
- PyShark / TShark / Scapy (Network Interception & Parsing)
- Scikit-Learn (Random Forest ML Engine)
- Yara-Python (Payload inspection)
- SQLite3 (Persistent storage)

---

## 🎯 The "Perfect Demo" Scenario

To see the platform at its maximum potential, run the included `sih_demo_dataset.pcapng` through the PCAP Ingest tool. This will trigger:
1. **Detection:** The AI engine will flag an anomaly due to mismatched cipher suites and anomalous byte distributions.
2. **Identification:** The YARA engine will match a simulated Cobalt Strike payload inside the hex dump.
3. **Active Response:** The IPS module will execute a firewall block against the source IP, and the SOC alerter will dispatch a critical warning to the terminal!

---

*Developed by Team Lakshya for SIH 2026. Empowering cyber defenders with the tools of tomorrow.*
