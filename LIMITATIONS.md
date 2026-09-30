# SecureMailScope - System Limitations & Disclaimers

## Overview
SecureMailScope is designed as a deep-inspection engine for cryptographic and network analysis of email protocols. To maintain strict **Error Honesty** and prevent "security theater," the following limitations are explicitly documented. The platform currently **CANNOT** perform the following tasks, and it will intentionally raise degraded states (e.g., `ML_UNAVAILABLE`, `CTI_OFFLINE`, `MITIGATION_FAILED`) rather than hallucinate success.

## 1. Network & Protocol Limitations
- **Encrypted Payload Decryption**: The system CANNOT decrypt TLS payloads unless it has access to the pre-master secret or private key (which it does not natively possess for active traffic). It performs deep analysis on the handshake and unencrypted metadata, not the application-layer payload inside the tunnel.
- **Implicit vs. Explicit TLS Decoding**: While it can detect STARTTLS commands (Explicit TLS) and Implicit TLS on standard ports, it cannot reliably reconstruct application-layer anomalies inside fragmented TCP streams if the stream is severely out-of-order or heavily obfuscated by advanced evasion techniques (AETs).

## 2. Threat Intelligence (CTI) Limitations
- **Rate Limiting**: The VirusTotal integration uses a free/standard API tier by default. If rate limits are exceeded, the system will explicitly report `CTI_UNAVAILABLE` rather than defaulting to "Clean".
- **Local Database Dependency**: The offline OSINT database relies on static snapshots. Zero-day threats or newly spun-up malicious infrastructure will not be detected by the local database alone.
- **False Negatives**: A lack of findings in CTI does NOT mean the IP/hash is benign; it only means it is not in the queried databases.

## 3. Machine Learning Limitations
- **Cold Start Problem**: The `MLAnomalyDetector` requires a pre-trained `ai_engine_real.pkl` model. If the model is absent or corrupt, the system will explicitly report `ML_UNAVAILABLE`. It will not randomly generate anomaly scores.
- **Concept Drift**: The Isolation Forest model is trained on a specific baseline. If the network topology or standard traffic behavior changes significantly, the model may generate false positives until retrained.

## 4. Active Response (IPS/SOAR) Limitations
- **OS Dependency & Privileges**: The IPS engine relies on OS-level firewall commands (`netsh` on Windows, `iptables` on Linux). If the backend is running without Administrator/Root privileges, active blocking will fail. The system will explicitly report `MITIGATION_FAILED` or `PARTIAL_MITIGATION` in this scenario, though it will fall back to logging in a local blocklist file.
- **Distributed Attacks**: The current SOAR playbook generation is limited to blocking individual IPs. It does not dynamically interact with upstream BGP routers or cloud WAFs to mitigate large-scale DDoS attacks.

## 5. UI & Forensic Limitations
- **Packet Truncation**: Only the first 512 bytes of a payload are currently rendered in the hex dump to prevent browser memory exhaustion. 
- **Missing Data**: If forensic details (like JA3 hash or certificate chain) cannot be parsed from the PCAP, the UI will display "Unavailable" or "Missing" rather than fabricating placeholder data.

---
**Ultimate Standard:** *REAL INPUT → REAL PROCESSING → VALID RESULT → CORRECT DOWNSTREAM CONSEQUENCE → VERIFIABLE EVIDENCE.*
