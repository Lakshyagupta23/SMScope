"""Bounded, offline TShark dissection with directional TCP evidence reconstruction.

Selected TLS parameters come exclusively from ServerHello. Observed records do
not establish authentication, successful Finished verification or absence of loss.
"""
import collections
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
import certificate_analyzer
from parser_streams import Direction, plaintext_events, starttls_state

PORT_PROTOCOL_MAP = {"25": "SMTP", "587": "SMTP (Submission)", "465": "SMTPS (Implicit TLS)",
                     "110": "POP3", "995": "POP3S (Implicit TLS)", "143": "IMAP", "993": "IMAPS (Implicit TLS)"}
IMPLICIT_TLS_PORTS = {"465", "993", "995"}
VERSIONS = {0x300: "SSLv3", 0x301: "TLSv1.0", 0x302: "TLSv1.1", 0x303: "TLSv1.2", 0x304: "TLSv1.3"}
# IANA TLS Cipher Suites registry snapshot, common email suites (2026-09).
# Remaining assigned values use the installed TShark numeric registry, never an offer.
CIPHER_REGISTRY = {0x0004: "TLS_RSA_WITH_RC4_128_MD5", 0x0005: "TLS_RSA_WITH_RC4_128_SHA",
                   0x0009: "TLS_RSA_WITH_DES_CBC_SHA", 0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                   0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA", 0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
                   0x003c: "TLS_RSA_WITH_AES_128_CBC_SHA256", 0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
                   0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384", 0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                   0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                   0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                   0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
                   0x1303: "TLS_CHACHA20_POLY1305_SHA256", 0x1304: "TLS_AES_128_CCM_SHA256", 0x1305: "TLS_AES_128_CCM_8_SHA256"}


class PcapParseError(RuntimeError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def identify_protocol_from_port(src_port, dst_port):
    return PORT_PROTOCOL_MAP.get(str(dst_port)) or PORT_PROTOCOL_MAP.get(str(src_port)) or "UNKNOWN"


def calculate_entropy(data_hex):
    try:
        data = bytes.fromhex(data_hex)
    except ValueError:
        return 0.0
    return -sum((count / len(data)) * math.log2(count / len(data)) for count in collections.Counter(data).values()) if data else 0.0


def _fields(node, name):
    return [f for f in node.iter("field") if f.get("name") == name]


def _show(node, name, default=None):
    fields = _fields(node, name)
    return fields[0].get("show", default) if fields else default


def _number(node, name, default=None):
    val = _show(node, name)
    if val is None:
        return default
    try:
        return int(val, 16 if val.lower().startswith("0x") else 10)
    except ValueError:
        return default


def _numbers(node, name):
    return [int(f.get("show"), 16 if f.get("show", "").startswith("0x") else 10) for f in _fields(node, name) if re.fullmatch(r"(?:0x[0-9a-fA-F]+|[0-9]+)", f.get("show", ""))]


def canonical_ja3(version, ciphers, extensions, groups, formats):
    def values(items, grease=True):
        return "-".join(str(x) for x in items if not grease or not (x & 0x0f0f == 0x0a0a and x >> 8 == x & 255))
    raw = f"{version},{values(ciphers)},{values(extensions)},{values(groups)},{values(formats, False)}"
    return {"raw": raw, "hash": hashlib.md5(raw.encode("ascii")).hexdigest(), "source": "canonical_numeric_fields"}


def _hello(session, packet, frame, direction):
    for hello in _fields(packet, "tls.handshake"):
        kind = _number(hello, "tls.handshake.type")
        if kind == 1 and direction == "client_to_server":
            session["_client_hello"] = True
            session["offered_versions"] = [VERSIONS.get(v, f"0x{v:04x}") for v in _numbers(hello, "tls.handshake.extensions.supported_version")]
            legacy = _number(hello, "tls.handshake.version")
            session["client_hello_legacy_version"] = VERSIONS.get(legacy)
            session["ciphers"] = [f"0x{v:04x}" for v in _numbers(hello, "tls.handshake.ciphersuite")]
            raw, digest = _show(hello, "tls.handshake.ja3_full"), _show(hello, "tls.handshake.ja3")
            if raw and digest:
                session["ja3"] = {"raw": raw, "hash": digest, "source": "tshark"}
            elif legacy is not None:
                session["ja3"] = canonical_ja3(legacy, _numbers(hello, "tls.handshake.ciphersuite"),
                    _numbers(hello, "tls.handshake.extension.type"), _numbers(hello, "tls.handshake.extensions_supported_group"),
                    _numbers(hello, "tls.handshake.extensions_ec_point_format"))
            session["server_name_indication"] = _show(hello, "tls.handshake.extensions_server_name")
            session["_early_data"] |= 42 in _numbers(hello, "tls.handshake.extension.type")
        elif kind == 2 and direction == "server_to_client":
            # HelloRetryRequest is encoded as ServerHello, but not a final selection.
            randoms = _fields(hello, "tls.handshake.random")
            if randoms and randoms[0].get("value", "").lower() == "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c":
                session["hello_retry_request_seen"] = True
                continue
            session["_server_hello"] = True
            version = _number(hello, "tls.handshake.extensions.supported_version", _number(hello, "tls.handshake.version"))
            selected = _number(hello, "tls.handshake.ciphersuite")
            session["tls_version"] = VERSIONS.get(version)
            session["selected_version_hex"] = f"0x{version:04x}" if version is not None else None
            session["cipher_suite_hex"] = f"0x{selected:04x}" if selected is not None else None
            session["cipher_suite_id"] = selected
            session["cipher_suite"] = CIPHER_REGISTRY.get(selected)
            fields = _fields(hello, "tls.handshake.ciphersuite")
            if not session["cipher_suite"] and fields:
                match = re.search(r"\b(TLS_[A-Z0-9_]+)\b", fields[0].get("showname", ""))
                session["cipher_suite"] = match.group(1) if match else None
            extensions = _numbers(hello, "tls.handshake.extension.type")
            session["server_key_share"] = bool(_fields(hello, "tls.handshake.extensions_key_share_key_exchange")) if 51 in extensions else False
            # Some TShark versions name this field differently: the key exchange
            # length plus a selected group also establishes an actual share.
            if 51 in extensions:
                session["server_key_share"] = any("key_share" in f.get("name", "") and ("key_exchange" in f.get("name", "") or "group" in f.get("name", "")) for f in hello.iter("field"))
            session["server_psk_selected"] = 41 in extensions
            session["selected_parameters_packet"] = frame
        elif kind == 11 and direction == "server_to_client":
            for field in _fields(hello, "tls.handshake.certificate"):
                try:
                    data = bytes.fromhex(field.get("value", ""))
                    certificate_analyzer.load_exact_der(data)
                    if data not in session["_der_chain"]:
                        if len(session["_der_chain"]) >= 16 or sum(map(len, session["_der_chain"])) + len(data) > 1048576:
                            raise PcapParseError("RESOURCE_LIMIT", "Certificate chain exceeds limit")
                        session["_der_chain"].append(data)
                except ValueError as exc:
                    session["certificate_errors"].append(str(exc))


def _port_config(extra):
    ports = dict(PORT_PROTOCOL_MAP)
    if extra is None:
        text = os.getenv("SECUREMAILSCOPE_EMAIL_PORTS", "")
        extra = json.loads(text) if text else {}
    if isinstance(extra, (list, tuple, set)):
        extra = {str(p): "EMAIL (Configured port)" for p in extra}
    for port, protocol in extra.items():
        p = int(port)
        if not 1 <= p <= 65535 or not re.fullmatch(r"(?:SMTP|SMTPS|IMAP|IMAPS|POP3|POP3S|EMAIL)(?: .*)?", protocol):
            raise ValueError("Email ports must map valid TCP ports to SMTP/IMAP/POP3 service names")
        ports[str(p)] = protocol
    return ports


def _run_tshark(file_path, output, errors, ports, timeout, output_limit):
    executable = os.getenv("TSHARK_PATH") or shutil.which("tshark")
    if not executable:
        executable = next((p for p in (r"D:\Wireshark\tshark.exe", r"C:\Program Files\Wireshark\tshark.exe") if Path(p).is_file()), None)
    if not executable:
        raise PcapParseError("PARSER_UNAVAILABLE", "TShark executable not found; configure TSHARK_PATH")
    display = "(" + " or ".join(f"tcp.port == {p}" for p in ports) + ") or smtp or imap or pop"
    args = [executable, "-n", "-r", str(file_path), "-Y", display, "-T", "pdml",
            "-o", "tcp.desegment_tcp_streams:TRUE", "-o", "tls.desegment_ssl_records:TRUE",
            "-o", "tls.desegment_ssl_application_data:TRUE", "-o", "tls.keylog_file:"]
    for port, proto in ports.items():
        if port not in PORT_PROTOCOL_MAP:
            decoder = "tls" if proto.split()[0] in ("SMTPS", "IMAPS", "POP3S") else {"SMTP": "smtp", "IMAP": "imap", "POP3": "pop"}.get(proto.split()[0])
            if decoder:
                args += ["-d", f"tcp.port=={port},{decoder}"]
    env = dict(os.environ, SSLKEYLOGFILE="")
    try:
        process = subprocess.Popen(args, stdout=output, stderr=errors, env=env)
    except OSError as exc:
        raise PcapParseError("PARSER_UNAVAILABLE", str(exc)) from exc
    deadline = time.monotonic() + timeout
    try:
        while process.poll() is None:
            if time.monotonic() >= deadline:
                raise PcapParseError("PARSER_TIMEOUT", f"TShark exceeded {timeout} seconds")
            if os.fstat(output.fileno()).st_size > output_limit or os.fstat(errors.fileno()).st_size > 1048576:
                raise PcapParseError("RESOURCE_LIMIT", "TShark output exceeds configured limit")
            time.sleep(0.025)
        if os.fstat(output.fileno()).st_size > output_limit:
            raise PcapParseError("RESOURCE_LIMIT", "TShark output exceeds configured limit")
        if process.returncode:
            errors.seek(0)
            message = errors.read(4096).decode("utf-8", errors="replace").strip()
            raise PcapParseError("INVALID_CAPTURE_OR_DISSECTION_FAILED", message or f"TShark exited {process.returncode}")
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()


def parse_pcap(file_path, *, email_ports=None, timeout=60, max_capture_bytes=134217728,
               max_output_bytes=268435456, max_sessions=2048, max_direction_bytes=524288,
               max_total_payload_bytes=16777216, trust_anchors=None, expected_identity=None):
    """Return legacy-compatible sessions, or raise PcapParseError (never fake [])."""
    try:
        path = Path(file_path)
        if not path.is_file():
            raise PcapParseError("INVALID_INPUT", "Capture does not exist or is not a regular file")
        if path.stat().st_size > max_capture_bytes:
            raise PcapParseError("RESOURCE_LIMIT", "Capture exceeds configured byte limit")
        ports = _port_config(email_ports)
        if min(timeout, max_output_bytes, max_sessions, max_direction_bytes, max_total_payload_bytes) <= 0:
            raise ValueError("Parser limits must be positive")
        if trust_anchors is None and os.getenv("SECUREMAILSCOPE_TRUST_ANCHORS"):
            from cryptography import x509
            anchor_path = Path(os.environ["SECUREMAILSCOPE_TRUST_ANCHORS"])
            if anchor_path.stat().st_size > 4194304:
                raise ValueError("Trust anchor file exceeds 4 MiB")
            trust_anchors = x509.load_pem_x509_certificates(anchor_path.read_bytes())
        expected_identity = expected_identity or os.getenv("SECUREMAILSCOPE_EXPECTED_IDENTITY")
        sessions, retained = {}, 0
        with tempfile.TemporaryFile("w+b") as output, tempfile.TemporaryFile("w+b") as errors:
            _run_tshark(path, output, errors, ports, timeout, max_output_bytes)
            output.seek(0)
            context = ET.iterparse(output, events=("start", "end"))
            _, root = next(context)
            for event, packet in context:
                if event != "end" or packet.tag != "packet":
                    continue
                stream = _show(packet, "tcp.stream")
                src = _show(packet, "ip.src") or _show(packet, "ipv6.src")
                dst = _show(packet, "ip.dst") or _show(packet, "ipv6.dst")
                if stream is None or src is None:
                    root.remove(packet)
                    continue
                sport, dport = _show(packet, "tcp.srcport"), _show(packet, "tcp.dstport")
                timestamp = float(_show(packet, "frame.time_epoch", "0"))
                frame = _number(packet, "frame.number", 0)
                if stream not in sessions:
                    if len(sessions) >= max_sessions:
                        raise PcapParseError("RESOURCE_LIMIT", "Too many email TCP streams")
                    # Canonical orientation follows service endpoint, or initial SYN.
                    reverse = sport in ports and dport not in ports
                    ci, si, cp, sp = (dst, src, dport, sport) if reverse else (src, dst, sport, dport)
                    inferred = ports.get(sp, "UNKNOWN")
                    sessions[stream] = dict(stream_index=stream, src_ip=ci, dst_ip=si, src_port=cp, dst_port=sp,
                        email_protocol=inferred, inferred_service=inferred, observed_application_protocol=None,
                        protocol_identification_status="PORT_INFERRED", protocols=set(),
                        is_implicit_tls=sp in IMPLICIT_TLS_PORTS or inferred.split()[0] in ("SMTPS", "IMAPS", "POP3S"),
                        starttls_seen=False, starttls_advertised=False, starttls_commanded=False, starttls_ready=False,
                        starttls_stripped=None, tls_version=None, cipher_suite=None, cipher_suite_hex=None,
                        cipher_suite_id=None, key_exchange=None, forward_secrecy=None, ciphers=[], offered_versions=[],
                        certificates=[], cert_count=0, certificate_errors=[], ja3=None, hex_dump=None,
                        packet_count=0, total_bytes=0, start_time=timestamp, end_time=timestamp, flow_duration=0,
                        inter_arrival_times=[], mean_iat=0, payload_entropy=0, is_known_malicious=False,
                        server_key_share=None, server_psk_selected=None, _client_hello=False, _server_hello=False,
                        _der_chain=[], _early_data=False, _tls_frames=[], _iat_sum=0, _last_time=timestamp,
                        _capture_truncated=False, _directions={"client_to_server": Direction(max_direction_bytes), "server_to_client": Direction(max_direction_bytes)})
                s = sessions[stream]
                direction = "client_to_server" if (src, sport) == (s["src_ip"], s["src_port"]) else "server_to_client"
                s["packet_count"] += 1
                s["total_bytes"] += _number(packet, "frame.len", 0)
                s["_iat_sum"] += max(0, timestamp - s["_last_time"])
                s["_last_time"] = timestamp
                s["start_time"], s["end_time"] = min(s["start_time"], timestamp), max(s["end_time"], timestamp)
                s["_capture_truncated"] |= _number(packet, "frame.cap_len", 0) < _number(packet, "frame.len", 0)
                raw_fields = _fields(packet, "tcp.payload")
                payload = bytes.fromhex(raw_fields[0].get("value", "")) if raw_fields else b""
                if _number(packet, "tcp.len", 0) > len(payload):
                    s["_capture_truncated"] = True
                d = s["_directions"][direction]
                before = d.retained
                d.add(_number(packet, "tcp.seq_raw", 0), payload, frame,
                      syn=_show(packet, "tcp.flags.syn") in ("1", "True"),
                      fin=_show(packet, "tcp.flags.fin") in ("1", "True"),
                      rst=_show(packet, "tcp.flags.reset") in ("1", "True"))
                retained += d.retained - before
                if retained > max_total_payload_bytes:
                    raise PcapParseError("RESOURCE_LIMIT", "Total retained TCP payload exceeds limit")
                protos = {p.get("name") for p in packet.iter("proto")}
                if "tls" in protos and _fields(packet, "tls.record"):
                    s["protocols"].add("TLS")
                    if len(s["_tls_frames"]) < 8192:
                        s["_tls_frames"].append(frame)
                    _hello(s, packet, frame, direction)
                for proto, label in (("smtp", "SMTP"), ("imap", "IMAP"), ("pop", "POP3")):
                    if proto in protos:
                        s["protocols"].add(label)
                root.remove(packet)
        return [_finish(s, trust_anchors, expected_identity) for s in sessions.values()]
    except PcapParseError:
        raise
    except Exception as exc:
        raise PcapParseError("PARSER_FAILED", f"Capture parsing failed: {exc}") from exc


def _finish(s, trust_anchors, expected_identity):
    reassembly, events, plaintext = {}, [], {}
    for name, direction in s["_directions"].items():
        reassembly[name], internal = direction.finish()
        ev, text = plaintext_events(internal, name)
        events.extend(ev)
        plaintext[name] = text
    client_lines = [e[3].upper() for e in events if e[1] == "client_to_server"]
    server_lines = [e[3].upper() for e in events if e[1] == "server_to_client"]
    observed = None
    if any(re.match(r"(?:EHLO |HELO |MAIL FROM:|RCPT TO:)", line) for line in client_lines) or any(re.match(r"220 .*\b(?:E?SMTP)\b", line) for line in server_lines):
        observed = "SMTP"
    elif any(re.match(r"\S+ (?:CAPABILITY|STARTTLS|LOGIN|SELECT|LOGOUT)(?: |$)", line) for line in client_lines) or any(line.startswith("* OK") for line in server_lines):
        observed = "IMAP"
    elif any(line.startswith("+OK") for line in server_lines) or any(line in ("STLS", "CAPA") for line in client_lines):
        observed = "POP3"
    s["observed_application_protocol"] = observed
    if observed:
        s["protocol_identification_status"] = "OBSERVED"
        s["email_protocol"] = observed
        s["protocols"].add(observed)
    elif any(line.startswith(("HTTP/", "GET ", "POST ", "SSH-")) for line in client_lines + server_lines):
        s["protocol_identification_status"] = "CONTRADICTED"
        s["email_protocol"] = "UNKNOWN"
    family = observed or next((p for p in ("SMTP", "IMAP", "POP3") if s["inferred_service"].startswith(p)), "UNKNOWN")
    upgrade = starttls_state(events, family, s["_tls_frames"])
    s.update(starttls=upgrade, starttls_seen=upgrade["advertised"] or upgrade["requested"],
             starttls_advertised=upgrade["advertised"], starttls_commanded=upgrade["requested"], starttls_ready=upgrade["accepted"])
    s["tcp_reassembly"] = reassembly
    gaps = any(r["gaps"] for r in reassembly.values())
    conflicts = any(r["conflicting_overlap_bytes"] for r in reassembly.values())
    truncated = s["_capture_truncated"] or any(r["truncated"] for r in reassembly.values())
    syns = all(r["syn_seen"] for r in reassembly.values())
    closed = all(r["fin_seen"] for r in reassembly.values()) or any(r["rst_seen"] for r in reassembly.values())
    s["capture_completeness"] = {"status": "INCOMPLETE" if gaps or conflicts or truncated or not syns or not closed else "OBSERVED_BOUNDED_STREAM",
                                 "syn_both_directions": syns, "closure_observed": closed, "gaps": gaps, "conflicting_overlaps": conflicts,
                                 "truncated": truncated, "reason": "Capture-wide loss and unobserved tail bytes cannot be excluded"}
    if gaps or conflicts or truncated:
        upgrade["evidence_status"] = "INCOMPLETE"
    else:
        upgrade["evidence_status"] = "OBSERVED_CONTIGUOUS" if syns else "MIDSTREAM"
    s["handshake_completeness"] = {"status": "HELLOS_OBSERVED" if s["_client_hello"] and s["_server_hello"] else "PARTIAL" if s["_client_hello"] or s["_server_hello"] else "NOT_VISIBLE",
                                    "client_hello": s["_client_hello"], "server_hello": s["_server_hello"],
                                    "authenticated_handshake_verified": None, "reason": "Finished and peer authentication are not verified by passive records"}
    tls = "TLS" in s["protocols"]
    text = b"\r\n".join(v for v in plaintext.values() if v)
    s["encryption_state"] = "TLS_OBSERVED" if tls else "PLAINTEXT_OBSERVED" if observed and text else "UNKNOWN"
    s["plaintext_payload_by_direction"] = {k: v.hex() for k, v in plaintext.items()}
    s["plaintext_payload_hex"] = text.hex()
    # Legacy scanner receives only observed plaintext, never encrypted TLS bytes.
    s["full_payload_hex"] = s["plaintext_payload_hex"]
    s["payload_scan"] = {"status": "AVAILABLE" if text else "NOT_VISIBLE", "scope": "Reassembled plaintext before TLS; MIME/attachments not decoded",
                         "ciphertext_status": "UNAVAILABLE", "reason": "TLS application content requires session secrets/decryption"}
    raw_preview = next((r["payload_hex"] for d in reassembly.values() for r in d["ranges"]), "")[:1024]
    s["hex_dump"] = "\n".join(raw_preview[i:i + 32] for i in range(0, len(raw_preview), 32)) or None
    s["payload_entropy"] = calculate_entropy(s["full_payload_hex"])
    s["payload_entropy_scope"] = "observed_plaintext"
    s["flow_duration"] = s["end_time"] - s["start_time"]
    s["mean_iat"] = s["_iat_sum"] / (s["packet_count"] - 1) if s["packet_count"] > 1 else 0
    s["inter_arrival_times_status"] = "ONLINE_MEAN_ONLY"
    s["forward_secrecy"] = certificate_analyzer.assess_forward_secrecy(s["cipher_suite"], s["tls_version"],
        key_share=s["server_key_share"], psk_selected=s["server_psk_selected"], early_data=s["_early_data"])
    cs = s["cipher_suite"] or ""
    if s["tls_version"] == "TLSv1.3":
        s["key_exchange"] = "(EC)DHE+PSK" if s["server_key_share"] and s["server_psk_selected"] else "(EC)DHE" if s["server_key_share"] else "PSK" if s["server_psk_selected"] else None
    else:
        s["key_exchange"] = next((p for p in ("ECDHE", "DHE", "ECDH", "DH", "RSA", "PSK") if f"_{p}_" in cs), None)
    s["certificates"] = [certificate_analyzer.analyze_certificate_from_der(c, s["start_time"]) for c in s["_der_chain"]]
    s["cert_count"] = len(s["certificates"])
    s["certificate_visibility"] = {"status": "OBSERVED" if s["cert_count"] else "NOT_VISIBLE",
                                    "reason": "Certificate records extracted" if s["cert_count"] else "TLS 1.3 encrypts certificates; no session keys used" if s["tls_version"] == "TLSv1.3" else "Certificate handshake absent, incomplete, or resumed"}
    identity = expected_identity.get(s["dst_ip"]) if isinstance(expected_identity, dict) else expected_identity
    s["certificate_validation"] = certificate_analyzer.validate_certificate_chain(s["_der_chain"], trust_anchors, identity, s["start_time"])
    s["assessment_status"] = "PARTIAL" if tls or observed else "INSUFFICIENT_EVIDENCE"
    s["evidence_coverage"] = {"selected_parameters": "OBSERVED" if s["_server_hello"] else "NOT_VISIBLE",
                              "certificate": s["certificate_visibility"]["status"], "tcp": s["capture_completeness"]["status"]}
    s["parser_provenance"] = {"engine": "tshark-pdml", "schema_version": "2", "cipher_registry": "IANA-common-2026-09 + installed TShark", "passive": True}
    s["protocols"] = sorted(s["protocols"])
    return {k: v for k, v in s.items() if not k.startswith("_")}


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise PcapParseError("INVALID_ARGUMENTS", "Usage: python pcap_parser.py <capture.pcap>")
        print(json.dumps(parse_pcap(sys.argv[1]), allow_nan=False))
    except PcapParseError as exc:
        print(json.dumps({"error": {"code": exc.code, "message": str(exc)}}), file=sys.stderr)
        sys.exit(1)
