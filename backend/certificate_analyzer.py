"""Offline X.509 evidence analysis. No network retrieval or implicit trust store."""
import datetime
import ipaddress
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448

UTC = datetime.timezone.utc


def _time(value=None):
    if value is None:
        return datetime.datetime.now(UTC)
    if isinstance(value, (int, float)):
        return datetime.datetime.fromtimestamp(value, UTC)
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def load_exact_der(data):
    cert = x509.load_der_x509_certificate(data)
    if cert.public_bytes(serialization.Encoding.DER) != data:
        raise ValueError("Certificate field is not exactly one canonical DER certificate")
    return cert


def analyze_certificate_from_der(der_bytes: bytes, capture_time=None) -> dict:
    result = dict(raw_subject=None, raw_issuer=None, serial_number=None,
                  not_valid_before=None, not_valid_after=None, is_expired=None,
                  is_not_yet_valid=None, days_until_expiry=None, public_key_algorithm=None,
                  public_key_bits=None, is_weak_key=None, signature_algorithm=None,
                  signature_algorithm_oid=None, is_weak_signature=None, subject_alt_names=[],
                  is_self_issued=None, is_self_signed=None, findings=[], severity="info",
                  status="NOT_VISIBLE", trust_status="NOT_CHECKED")
    try:
        cert = load_exact_der(der_bytes)
        when = _time(capture_time)
        before, after = cert.not_valid_before_utc, cert.not_valid_after_utc
        result.update(status="OBSERVED", raw_subject=cert.subject.rfc4514_string(),
                      raw_issuer=cert.issuer.rfc4514_string(), serial_number=str(cert.serial_number),
                      fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
                      not_valid_before=before.isoformat(), not_valid_after=after.isoformat(),
                      validation_time=when.isoformat(), time_basis="capture" if capture_time is not None else "analysis",
                      is_expired=when > after, is_not_yet_valid=when < before,
                      days_until_expiry=(after - when).days,
                      validity_status="EXPIRED" if when > after else "NOT_YET_VALID" if when < before else "VALID_AT_TIME",
                      is_self_issued=cert.subject == cert.issuer, is_self_signed=False)
        if result["is_self_issued"]:
            try:
                cert.verify_directly_issued_by(cert)
                result["is_self_signed"] = True
            except Exception:
                result["self_signature_status"] = "INVALID_OR_UNSUPPORTED"
        result.setdefault("self_signature_status", "VERIFIED" if result["is_self_signed"] else "NOT_APPLICABLE")
        key = cert.public_key()
        for cls, name in ((rsa.RSAPublicKey, "RSA"), (ec.EllipticCurvePublicKey, "ECDSA"),
                          (dsa.DSAPublicKey, "DSA"), (ed25519.Ed25519PublicKey, "Ed25519"),
                          (ed448.Ed448PublicKey, "Ed448")):
            if isinstance(key, cls):
                result["public_key_algorithm"] = name
                break
        result["public_key_bits"] = getattr(key, "key_size", 256 if isinstance(key, ed25519.Ed25519PublicKey) else 456 if isinstance(key, ed448.Ed448PublicKey) else None)
        result["is_weak_key"] = (isinstance(key, (rsa.RSAPublicKey, dsa.DSAPublicKey)) and key.key_size < 2048) or (isinstance(key, ec.EllipticCurvePublicKey) and key.key_size < 224)
        result["signature_algorithm_oid"] = cert.signature_algorithm_oid.dotted_string
        result["signature_algorithm"] = cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string
        sig_hash = cert.signature_hash_algorithm
        result["is_weak_signature"] = bool(sig_hash and sig_hash.name.lower() in ("md2", "md5", "sha1"))
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            result["subject_alt_names"] = san.get_values_for_type(x509.DNSName) + [str(x) for x in san.get_values_for_type(x509.IPAddress)]
        except x509.ExtensionNotFound:
            pass
        for flag, text in (("is_expired", "Certificate expired at validation time"),
                           ("is_not_yet_valid", "Certificate not yet valid at validation time"),
                           ("is_weak_key", "Weak certificate public key"),
                           ("is_weak_signature", "Weak certificate signature hash")):
            if result[flag]:
                result["findings"].append(text)
                result["severity"] = "high"
        # A valid self-signature says nothing about configured trust.
    except Exception as exc:
        result.update(status="ERROR", severity="error", findings=[f"Invalid certificate DER: {exc}"])
    return result


def validate_certificate_chain(der_chain, trust_anchors=None, expected_identity=None, capture_time=None):
    """RFC 5280/server identity policy via cryptography's offline path verifier.

    Trust anchors are explicit x509 certificates or DER bytes. No AIA/OCSP/CRL
    fetch occurs. Absence of an independently configured identity is not filled
    with attacker-controlled SNI. Both prerequisites are required by this policy.
    """
    result = {"status": "NOT_CHECKED", "trust_status": "NOT_CHECKED", "identity_status": "NOT_CHECKED",
              "revocation_status": "NOT_CHECKED", "revocation_reason": "No offline revocation evidence configured",
              "expected_identity": expected_identity, "time_basis": "capture" if capture_time is not None else "analysis"}
    if not der_chain:
        return {**result, "status": "NOT_VISIBLE", "reason": "No visible certificate chain"}
    if not trust_anchors or not expected_identity:
        return {**result, "reason": "Offline server verification requires configured trust anchors and expected identity"}
    try:
        from cryptography.x509.verification import PolicyBuilder, Store
        certs = [load_exact_der(c) for c in der_chain]
        anchors = [load_exact_der(c) if isinstance(c, bytes) else c for c in trust_anchors]
        try:
            subject = x509.IPAddress(ipaddress.ip_address(expected_identity))
        except ValueError:
            subject = x509.DNSName(expected_identity.encode("idna").decode("ascii"))
        verifier = PolicyBuilder().store(Store(anchors)).time(_time(capture_time)).max_chain_depth(8).build_server_verifier(subject)
        chain = verifier.verify(certs[0], certs[1:])
        result.update(status="VALID", trust_status="VALID", identity_status="VALID", reason="Offline server path and identity policy validated",
                      verified_chain_sha256=[c.fingerprint(hashes.SHA256()).hex() for c in chain])
    except ImportError:
        result.update(reason="Installed cryptography lacks the offline policy verifier")
    except Exception as exc:
        # A combined verifier failure cannot establish which individual control failed.
        result.update(status="INVALID", trust_status="INDETERMINATE", identity_status="INDETERMINATE", reason=str(exc))
    return result


def extract_certs_from_pyshark_packet(packet, capture_time=None) -> list:
    if not hasattr(packet, "tls"):
        return []
    fields = packet.tls.get_field("handshake_certificate")
    if not fields:
        return []
    values = getattr(fields, "all_fields", [fields])
    results = []
    for field in values:
        try:
            data = bytes.fromhex(str(field.get_default_value()).replace(":", ""))
            results.append(analyze_certificate_from_der(data, capture_time if capture_time is not None else float(packet.sniff_timestamp)))
        except Exception as exc:
            results.append({"status": "ERROR", "severity": "error", "findings": [f"Certificate extraction failed: {exc}"]})
    return results


_TLS13_CIPHER_SUITES = {"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_CCM_SHA256", "TLS_AES_128_CCM_8_SHA256"}


def assess_forward_secrecy(cipher_suite, tls_version=None, key_share=None, psk_selected=None, psk_mode=None, early_data=False):
    def answer(value, reason):
        return {"has_forward_secrecy": value, "status": "OBSERVED" if value is not None else "NOT_ENOUGH_EVIDENCE", "reason": reason,
                "early_data_forward_secrecy": False if early_data else None}
    cs = (cipher_suite or "").upper()
    is13 = tls_version == "TLSv1.3"
    if cs in _TLS13_CIPHER_SUITES and tls_version and not is13:
        return answer(None, "Contradictory negotiated version and cipher suite")
    if is13:
        if cs and cs.startswith("TLS_") and cs not in _TLS13_CIPHER_SUITES and not cs.startswith("TLS_EMPTY_RENEGOTIATION"):
            return answer(None, "Contradictory negotiated version and cipher suite")
        if psk_selected is True and (psk_mode == "psk_ke" or key_share is False):
            return answer(False, "ServerHello selects PSK without a key_share (psk_ke)")
        return answer(True, "TLS 1.3 uses ephemeral key exchange by default")
    if cs in _TLS13_CIPHER_SUITES:
        return answer(None, "TLS 1.3 cipher alone does not identify key exchange")
    if "ECDHE_" in cs or "DHE_" in cs:
        return answer(True, "Selected suite specifies ephemeral (EC)DHE key exchange")
    if "ECDH_" in cs or "_DH_" in cs:
        return answer(False, "Selected suite specifies static (EC)DH key exchange")
    if cs.startswith("TLS_RSA_") or "_PSK_WITH_" in cs:
        return answer(False, "Selected suite specifies non-ephemeral RSA or PSK key exchange")
    return answer(None, "No recognized selected key-exchange evidence")
