"""Legacy filename: explicitly upload an existing synthetic/offline PCAP for passive analysis."""
import argparse
import os
from pathlib import Path
import requests


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path, help="Existing capture; no traffic is generated")
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    token = os.getenv("SECUREMAILSCOPE_API_TOKEN", "")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        with args.capture.open("rb") as source:
            response = requests.post(args.url.rstrip("/") + "/api/pcap/upload", headers=headers,
                                     files={"file": (args.capture.name, source, "application/vnd.tcpdump.pcap")}, timeout=180)
        response.raise_for_status()
        result = response.json()
        print("Offline capture analysis:", result.get("status", "unknown"))
        print("Analysis ID:", result.get("analysis_id", "unavailable"))
        print("No live attack, firewall response, or SOC notification is performed by this helper.")
        return 0 if result.get("status") in ("success", "no_sessions") else 1
    except (OSError, requests.RequestException, ValueError):
        print("Upload did not complete. Check the capture path, API authentication and backend readiness.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
