"""Passive, evidence-scoped cryptographic posture rules.

Scores are heuristic deductions, never attack probabilities. This module has no
firewall, alert, or other response integration. Optional enrichments do not change
cryptographic posture scores or establish malicious intent.
"""
import copy
import json
import re
import sys

import anomaly_detector
import threat_intel
from yara_engine import scan_plaintext

RULESET_VERSION = "securemailscope.posture.v3"
_VERSIONS = {"0x0002": "SSLv2", "0x0300": "SSLv3", "0x0301": "TLSv1.0",
             "0x0302": "TLSv1.1", "0x0303": "TLSv1.2", "0x0304": "TLSv1.3"}
LIMITATIONS = [
    "The score is an uncalibrated heuristic posture index over observed controls, not an attack probability.",
    "Missing capture/handshake evidence is unknown, not proof of plaintext or secure configuration.",
    "A selected suite/version does not prove successful authentication or completion of a TLS handshake.",
    "Observed sessions do not enumerate all server capabilities or establish regulatory compliance, exploitation, or actor identity.",
    "Passive encrypted payloads are not decrypted; MIME/attachment reconstruction is not implemented.",
]


def _negotiated(session):
    evidence = session.get("handshake_evidence") or session.get("handshake_completeness") or {}
    if not isinstance(evidence, dict):
        evidence = {}
    server_hello = (session.get("server_hello_seen") is True or
                    evidence.get("server_hello_seen") is True or
                    evidence.get("server_hello") is True or
                    session.get("negotiated_parameters_source") == "server_hello")
    selected = session.get("selected_parameters") or {}
    if not isinstance(selected, dict):
        selected = {}
    version = session.get("selected_tls_version") or selected.get("tls_version")
    cipher = session.get("selected_cipher_suite") or selected.get("cipher_suite")
    if server_hello:
        version = version or session.get("tls_version")
        cipher = cipher or session.get("cipher_suite")
    if version is not None:
        text = str(version).strip()
        version = _VERSIONS.get(text.lower(), text)
        aliases = {"TLS1.0": "TLSv1.0", "TLS1.1": "TLSv1.1", "TLS1.2": "TLSv1.2", "TLS1.3": "TLSv1.3"}
        version = aliases.get(version.upper().replace(" ", ""), version)
    # Numeric/unknown suite codes and unrecognized versions remain unassessed.
    if version not in _VERSIONS.values():
        version = None
    if (not isinstance(cipher, str) or not re.fullmatch(r"(?:TLS|SSL)_[A-Za-z0-9_]+", cipher)
            or "UNKNOWN" in cipher.upper()):
        cipher = None
    return version, cipher, server_hello or bool(selected) or bool(session.get("selected_tls_version") or session.get("selected_cipher_suite"))


def _yara(session, encryption_state):
    # Only explicit plaintext buffers qualify. Never use a TLS hex dump as plaintext.
    payload = session.get("plaintext_payload_hex")
    confirmed = isinstance(payload, str)
    if payload is None and session.get("payload_is_plaintext") is True:
        payload = session.get("full_payload_hex") or session.get("hex_dump")
        confirmed = True
    if not confirmed:
        return scan_plaintext(b"", plaintext_confirmed=False)
    try:
        raw = bytes.fromhex(payload.replace(":", "")) if isinstance(payload, str) else b""
    except ValueError:
        return {"status": "unavailable", "matches": [], "reason": "Malformed plaintext hex buffer."}
    return scan_plaintext(raw, plaintext_confirmed=True)


def evaluate_session_risk(session: dict) -> dict:
    if not isinstance(session, dict):
        raise TypeError("session must be a dictionary")
    result = copy.deepcopy(session)  # retain timestamps, packet references, provenance and negotiation state
    result["raw_session"] = copy.deepcopy(session.get("raw_session", session))
    factors, remediations, observations = [], [], []
    deductions = {}
    controls = {}
    tls_ver, cipher, selected = _negotiated(session)
    encryption_state = str(session.get("encryption_state") or "unknown").lower()
    plaintext = (encryption_state in ("plaintext", "plaintext_observed", "cleartext_observed") or
                 session.get("plaintext_application_observed") is True)
    tls_observed = encryption_state in ("encrypted", "tls", "tls_observed", "encrypted_application_data")
    controls["encryption"] = "observed_plaintext" if plaintext else "observed_tls" if tls_observed else "unknown"
    capture = session.get("capture_completeness") or {}
    controls["capture_completeness"] = ("assessed" if isinstance(capture, dict) and
        capture.get("status") in ("OBSERVED_BOUNDED_STREAM", "complete") else "unknown")

    def finding(code, penalty, severity, text, remediation):
        # One deduction per distinct control defect, regardless of duplicate DER/findings/retransmissions.
        if code not in deductions:
            deductions[code] = {"points": penalty, "severity": severity, "evidence": text}
            factors.append(text)
            remediations.append(remediation)

    if plaintext:
        finding("plaintext", 50, "critical", "PLAINTEXT OBSERVATION: Unencrypted application-protocol content was observed; scope is the captured bytes.",
                "Require TLS before credentials/message content; verify the complete protocol exchange and mail policy.")
    controls["tls_version"] = "assessed" if tls_ver else "not_applicable" if plaintext and not selected else "unknown"
    controls["cipher_suite"] = "assessed" if cipher else "not_applicable" if plaintext and not selected else "unknown"
    legacy = {"SSLv2": (45, "critical"), "SSLv3": (45, "critical"),
              "TLSv1.0": (30, "high"), "TLSv1.1": (20, "high")}
    if tls_ver in legacy:
        points, severity = legacy[tls_ver]
        finding("legacy_version", points, severity, f"LEGACY NEGOTIATED PROTOCOL: Server selected {tls_ver}. Exploitation is not established.",
                "Disable SSL/TLS 1.0/1.1; configure TLS 1.2 or TLS 1.3 and verify client compatibility.")
    if cipher:
        upper = cipher.upper()
        tokens = upper.split("_")
        weakness = next((label for matched, label in (
            ("3DES" in upper or "DES_EDE" in upper, "3DES (64-bit blocks)"),
            ("DES" in tokens, "single DES (56-bit key)"),
            ("RC4" in tokens, "RC4"), ("NULL" in tokens, "NULL encryption"),
            ("EXPORT" in tokens, "export-grade strength"),
            ("ANON" in tokens or "anon" in cipher or "ADH" in tokens or "AECDH" in tokens, "anonymous authentication"),
            ("MD5" in tokens, "legacy MD5-based suite")) if matched), None)
        if weakness:
            finding("weak_cipher", 30, "critical", f"WEAK NEGOTIATED CIPHER: {cipher}: {weakness}. This is a control weakness, not evidence of an attack.",
                    "Replace the selected weak suite with authenticated AEAD suites and ephemeral key exchange.")
        elif "CBC" in tokens:
            finding("cbc", 10, "elevated", f"CBC NEGOTIATED: {cipher}; implementation-specific padding/timing protections are not assessed.",
                    "Prefer AEAD suites such as AES-GCM or ChaCha20-Poly1305.")

    fs = session.get("forward_secrecy")
    fs = copy.deepcopy(fs) if isinstance(fs, dict) else {}
    if not selected:
        fs = {"has_forward_secrecy": None, "reason": "No reliable selected handshake parameters."}
    fs_val = fs.get("has_forward_secrecy")
    if fs_val is not True and fs_val is not False:
        fs["has_forward_secrecy"] = None
    controls["forward_secrecy"] = "assessed" if fs_val is True or fs_val is False else "not_applicable" if plaintext and not selected else "unknown"
    if fs_val is False:
        finding("no_forward_secrecy", 15, "high", f"NO FORWARD SECRECY: {fs.get('reason', 'Selected key exchange lacks forward secrecy.')}",
                "Enable ephemeral (EC)DHE key exchange; verify TLS 1.3 PSK modes and early-data policy separately.")

    certs = [c for c in (session.get("certificates") or []) if isinstance(c, dict)]
    parsed = [c for c in certs if c.get("severity") != "error" and c.get("parse_status") not in ("error", "unavailable")]
    # Each explicit property is scored once, not again via the human-readable findings.
    cert_checks = [
        ("is_expired", 30, "expired", "Renew the certificate and verify validity against capture time."),
        ("is_not_yet_valid", 30, "not yet valid", "Check certificate issuance and system/capture clocks."),
        ("is_weak_key", 20, "weak public key", "Replace the certificate/key with policy-approved key strength."),
        ("is_weak_signature", 15, "weak signature algorithm", "Replace certificates using deprecated signature algorithms."),
    ]
    for prop, points, label, remediation in cert_checks:
        matching = [c for c in parsed if c.get(prop) is True]
        if matching:
            basis = sorted({str(c.get("validation_time_basis", c.get("time_basis", "unspecified validation time"))) for c in matching})
            finding("certificate_" + prop, points, "critical", f"CERTIFICATE: Observed {label}; time basis: {', '.join(basis)}.", remediation)
    properties_known = bool(parsed) and all(all(c.get(prop) is True or c.get(prop) is False for prop, *_ in cert_checks) for c in parsed)
    controls["certificate_properties"] = "assessed" if properties_known else "not_applicable" if plaintext and not selected else "unknown"
    trust = session.get("certificate_validation") or session.get("trust_validation") or session.get("certificate_trust") or {}
    trust_status = str(trust.get("status", "unknown")).lower() if isinstance(trust, dict) else "unknown"
    controls["certificate_trust"] = "assessed" if trust_status in ("valid", "trusted", "invalid", "untrusted") else "not_applicable" if plaintext and not selected else "unknown"
    if trust_status in ("invalid", "untrusted"):
        finding("certificate_trust", 20, "high", "CERTIFICATE TRUST: Validation failed under the explicitly configured policy; see validation evidence.",
                "Review trust anchors, supplied intermediates, expected hostname, validation time, and the specific validation failure.")

    upgrade = session.get("starttls") or {}
    if (session.get("starttls_stripped") or session.get("starttls_state") in ("requested", "accepted", "rejected", "incomplete")
            or isinstance(upgrade, dict) and (upgrade.get("requested") or upgrade.get("advertised"))):
        observations.append("STARTTLS transition observation: inspect ordered protocol evidence; missing upgrade completion does not establish stripping or interception.")
    for field in ("payload_entropy", "mean_iat"):
        if session.get(field) is not None:
            observations.append(f"{field} is descriptive telemetry only; no malware or automation deduction is applied.")
    try:
        ml = anomaly_detector.ai_engine.assess(session)
    except Exception as exc:
        ml = {"status": "unavailable", "reason": f"ML assessment failed: {type(exc).__name__}"}
    try:
        cti = threat_intel.enrich_session(session)
    except Exception as exc:
        cti = {"status": "unavailable", "findings": [], "is_threat_actor": False,
               "reason": f"CTI assessment failed: {type(exc).__name__}"}
    yara = _yara(session, encryption_state)
    if ml.get("is_anomaly"):
        observations.append("Experimental ML baseline outlier; not a malicious-activity finding and not part of the posture score.")
    if cti.get("has_reputation_match"):
        observations.append("Exact reputation match(s) require contextual review; see the matched endpoint and feed provenance.")
    if yara.get("matches"):
        observations.append("Plaintext YARA rule match(s): " + ", ".join(yara["matches"]) + "; review matched content, not a confirmed malware classification.")
        remediations.append("Review the available plaintext rule matches in an isolated content-analysis workflow.")

    assessed = sum(value not in ("unknown", "not_applicable") for value in controls.values())
    total = sum(value != "not_applicable" for value in controls.values())
    posture_assessable = plaintext or tls_ver is not None or cipher is not None or fs_val is True or fs_val is False or properties_known or bool(deductions)
    assessment = "unassessable" if not posture_assessable else "incomplete" if "unknown" in controls.values() else "assessed"
    score = None if assessment == "unassessable" else max(0, 100 - sum(d["points"] for d in deductions.values()))
    severity = next((s for s in ("critical", "high", "elevated") if any(d["severity"] == s for d in deductions.values())), None)
    status = severity or ("secure" if assessment == "assessed" else "unknown")
    scoped = [{"control": name, "observation": state, "scope": "captured session only"} for name, state in controls.items()]
    cti["ml_status"] = "ASSESSED" if ml.get("status") == "assessed" else "ML_UNAVAILABLE"
    result.update({
        "email_protocol": session.get("email_protocol", "UNKNOWN"), "protocols": session.get("protocols", []),
        "tls_version": tls_ver, "cipher_suite": cipher, "forward_secrecy": fs,
        "encryption_state": encryption_state, "certificates": certs,
        "cert_count": session.get("cert_count", len(certs)),
        "score": score, "status": status, "assessment_status": assessment,
        "evidence_coverage": {"assessed": assessed, "total": total,
                              "percentage": round(100 * assessed / total, 1) if total else None,
                              "controls": controls},
        "score_semantics": "heuristic_posture_not_probability", "ruleset_version": RULESET_VERSION,
        "risk_factors": factors, "remediations": list(dict.fromkeys(remediations)),
        "score_deductions": deductions, "control_observations": scoped,
        "compliance": ["Not assessed: regulatory scope and additional controls are not established by this capture."],
        "observations": observations, "limitations": list(LIMITATIONS),
        "unknowns": [name for name, state in controls.items() if state == "unknown"],
        "threat_intel": cti, "ml_analysis": ml, "yara_analysis": yara,
        "component_statuses": {"ml": ml.get("status"), "cti": cti.get("status"), "yara": yara.get("status"),
                               "certificate_trust": trust_status},
        "response": {"status": "not_requested", "reason": "Passive analysis never performs enforcement or sends alerts."},
    })
    return result


def process_file(json_filepath):
    with open(json_filepath, "r", encoding="utf-8") as source:
        sessions = json.load(source)
    if not isinstance(sessions, list):
        raise ValueError("Expected a session array")
    print(json.dumps([evaluate_session_risk(s) for s in sessions], indent=2, default=str))


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("Usage: python risk_engine.py <parsed_sessions.json>")
        process_file(sys.argv[1])
    except Exception as exc:
        print(json.dumps({"status": "error", "message": str(exc)}), file=sys.stderr)
        sys.exit(1)
