import pytest
from fastapi.testclient import TestClient
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import main

def test_api_soar_deploy_fails_honestly():
    """Verify that SOAR deploy returns MITIGATION_FAILED if IPS fails entirely."""
    import unittest.mock as mock
    
    with TestClient(main.app) as client:
        with mock.patch("ips_engine.block_ip", return_value={"status": "FAILED", "reason": "Dry run"}), \
             mock.patch("main.get_history", return_value=[{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}]):
            response = client.post("/api/soar/deploy", json={"ips": ["10.0.0.1"], "analysis_id": "test_id", "confirm": True})
            assert response.status_code == 200
        data = response.json()
        assert data["status"] == "FAILED"
        assert data["ips_results"]["10.0.0.1"]["status"] == "FAILED"


def test_api_pcap_upload_fails_honestly():
    """Verify that an invalid PCAP results in PCAP_ANALYSIS_UNAVAILABLE or no_sessions, not fabricated success."""
    import tempfile
    
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(b"NOT A REAL PCAP")
        tmp.flush()
        tmp_name = tmp.name
        
    try:
        with open(tmp_name, "rb") as f:
            with TestClient(main.app) as client:
                response = client.post(
                    "/api/pcap/upload", 
                    files={"file": ("test.pcap", f, "application/vnd.tcpdump.pcap")}
                )
            
        assert response.status_code == 422
        data = response.json()
        # Either no_sessions (tshark ran but found nothing) or PCAP_ANALYSIS_UNAVAILABLE (tshark crashed/missing)
        assert data["detail"]["code"] in ["INVALID_CAPTURE_OR_DISSECTION_FAILED", "PARSER_UNAVAILABLE", "PARSER_FAILED"]
    finally:
        try:
            os.remove(tmp_name)
        except Exception:
            pass
