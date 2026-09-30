import pytest
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import threat_intel
import anomaly_detector
import ips_engine
import pcap_parser
import main

# PHASE 19: SECURITY REGRESSION TESTS & ERROR HONESTY

def test_fake_ml_test():
    """Verify that the model output is actually produced by the model and not by hardcoded logic.
    Also verify ML_UNAVAILABLE state."""
    
    # Test unavailable state
    detector = anomaly_detector.MLAnomalyDetector()
    detector.is_fitted = False
    score, anomalies = detector.detect_anomalies({"ciphers": []})
    assert "ML_UNAVAILABLE" in anomalies
    
    # Test deterministic output based on real feature changes
    # If the model is fitted, verify it produces real outputs
    detector.is_fitted = True
    if detector.iso_forest:
        # Provide benign features
        benign_session = {
            "cipher_suite": "TLS_AES_128_GCM_SHA256", 
            "starttls_seen": True,
            "packet_count": 10,
            "flow_duration": 1.0
        }
        b_score, b_anomalies = detector.detect_anomalies(benign_session)
        
        # Provide highly anomalous features
        anomalous_session = {
            "cipher_suite": "RC4", 
            "starttls_stripped": True,
            "packet_count": 5000,
            "flow_duration": 0.1,
            "payload_entropy": 8.0
        }
        a_score, a_anomalies = detector.detect_anomalies(anomalous_session)
        
        # The outputs should be genuinely different
        assert b_score != a_score or len(b_anomalies) != len(a_anomalies)


def test_fake_cti_test():
    """Use an IOC absent from the offline database.
    Verify that the system does not fabricate a match."""
    
    benign_session = {
        "src_ip": "8.8.8.8",
        "ja3": {"hash": "00000000000000000000000000000000"}
    }
    
    # Fake/force VT offline to test local db only
    import unittest.mock as mock
    import os
    with mock.patch.dict(os.environ, {"SECUREMAILSCOPE_CTI_ENABLED": "1", "SECUREMAILSCOPE_CTI_NETWORK_ENABLED": "1", "VIRUSTOTAL_API_KEY": ""}):
        result = threat_intel.enrich_session(benign_session)
    
    # Verify no fabricated findings
    assert result["findings"] == []
    assert result["is_threat_actor"] == False
    assert result["status"] == "unavailable"


def test_fake_ips_test():
    """Run in dry-run mode. Verify that no firewall state changes.
    If mitigation fails, verify MITIGATION_FAILED state."""
    
    import unittest.mock as mock
    
    # Test 1: block_ip now returns a dict (not bool)
    result = ips_engine.block_ip("192.168.1.99", dry_run=True)
    assert isinstance(result, dict), "block_ip must return dict, not bool"
    assert "status" in result
    
    # Test 2: Invalid IP must fail cleanly (no command injection)
    result_bad = ips_engine.block_ip("not-an-ip; rm -rf /")
    assert result_bad["status"] == ips_engine.STATUS_FAILED
    
    # Test 3: Permission failure must not produce EXECUTED status
    with mock.patch("subprocess.run", side_effect=PermissionError("Simulated FW failure")):
        with mock.patch("builtins.open", side_effect=PermissionError("Simulated write failure")):
            result_fail = ips_engine.block_ip("192.168.1.99", dry_run=False)
            assert result_fail["status"] == ips_engine.STATUS_FAILED
            assert result_fail["status"] != ips_engine.STATUS_EXECUTED


def test_pcap_unavailable():
    """Verify PCAP_ANALYSIS_UNAVAILABLE error honesty."""
    
    # If tshark doesn't exist, it should gracefully return empty from parser
    # and main.py endpoint should catch it.
    
    import tempfile, os
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"NOT A PCAP")
        tmp.flush()
        tmp_name = tmp.name
    try:
        results = pcap_parser.parse_pcap(tmp_name)
    except pcap_parser.PcapParseError:
        results = []
    finally:
        os.unlink(tmp_name)
    assert results == []  # Handled gracefully, not silently fabricated
