"""Complete evidence exports sharing one report schema, without security certification."""
import datetime as dt
import html
import io
import ipaddress
import json
import math
import textwrap
import uuid

REPORT_SCHEMA = "securemailscope.report.v3"
REPORT_LIMITATIONS = [
    "Scores are heuristic posture indices over observed controls, not probabilities of attack.",
    "Unknown and incomplete assessments are not secure findings; averages exclude null scores and do not override critical findings.",
    "Certificate trust, revocation, endpoint identity, capture completeness and encrypted content may be unassessed; consult each session's evidence.",
    "This report is not a compliance certification or evidence of attacker identity/exploitation.",
    "CTI and experimental ML/YARA observations require independent contextual review; no automatic response is performed by scoring.",
]


def _now():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _valid_score(value):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 100


def _classify_overall(avg_score):
    """Legacy score-only label, deliberately not a security/compliance verdict."""
    if not _valid_score(avg_score):
        return "UNKNOWN - No assessable posture score"
    return "Heuristic observed-control score only; consult findings and evidence coverage"


def _extract_key_findings(sessions):
    return list(dict.fromkeys(str(f) for s in sessions for f in (s.get("risk_factors") or [])))


def _report(evaluated_sessions):
    sessions = list(evaluated_sessions)
    groups = {status: [] for status in ("critical", "high", "elevated", "secure", "unknown")}
    for session in sessions:
        groups[session.get("status") if session.get("status") in groups else "unknown"].append(session)
    scores = [s["score"] for s in sessions if _valid_score(s.get("score"))]
    incomplete = sum(s.get("assessment_status") != "assessed" for s in sessions)
    worst = next((status for status in ("critical", "high", "elevated") if groups[status]), None)
    classification = (worst.upper() + " - Observed control weaknesses; review session evidence" if worst else
                      "UNKNOWN / INCOMPLETE - Evidence gaps remain" if incomplete or not sessions else
                      "No rule deductions in the assessed scope; not a security or compliance certification")
    return {
        "report_metadata": {"tool": "SecureMailScope", "version": "3.0.0", "schema_version": REPORT_SCHEMA,
                            "generated_at": _now(),
                            "analysis_ids": sorted({str(s["analysis_id"]) for s in sessions if s.get("analysis_id")})},
        "executive_summary": {"total_streams_analyzed": len(sessions),
                              "scored_streams": len(scores), "unscored_streams": len(sessions) - len(scores),
                              "incomplete_or_unassessed_streams": incomplete,
                              "average_posture_score": round(sum(scores) / len(scores), 1) if scores else None,
                              "overall_classification": classification,
                              "streams_by_severity": {k: len(v) for k, v in groups.items()},
                              "key_findings": _extract_key_findings(sessions)},
        "limitations": REPORT_LIMITATIONS,
        "prioritized_findings": groups,
        "all_sessions": sessions,
    }


def generate_json_report(evaluated_sessions):
    return json.dumps(_report(evaluated_sessions), indent=2, default=str, ensure_ascii=True)


def generate_html_report(evaluated_sessions):
    # A complete escaped JSON evidence document makes every raw field available,
    # including timestamps, provenance, certificate trust, unknowns and remediation.
    report = _report(evaluated_sessions)
    evidence = html.escape(json.dumps(report, indent=2, default=str, ensure_ascii=True), quote=True)
    summary = html.escape(report["executive_summary"]["overall_classification"], quote=True)
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>SecureMailScope evidence report</title>
<style>body{{font-family:system-ui,sans-serif;margin:2rem;color:#18222e}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;padding:1rem;background:#f1f4f8}}h1{{font-size:1.6rem}}</style>
</head><body><h1>SecureMailScope — cryptographic posture evidence</h1>
<p>{summary}</p><p>Complete evidence, unknowns, provenance, trust observations, limitations and remediations:</p>
<pre>{evidence}</pre></body></html>'''


def generate_pdf_report(evaluated_sessions):
    """Render the same complete JSON evidence as HTML/JSON, without truncation.

    JSON ASCII escapes preserve arbitrary Unicode/control characters exactly even
    when the PDF's built-in font cannot render them. Long values wrap across pages.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    except ImportError as exc:
        raise RuntimeError("PDF generation unavailable: reportlab is not installed") from exc
    report = _report(evaluated_sessions)
    buffer = io.BytesIO()
    document = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    styles = getSampleStyleSheet()
    code = ParagraphStyle("Evidence", fontName="Courier", fontSize=7, leading=9, spaceAfter=0,
                          splitLongWords=True)
    content = [Paragraph("SecureMailScope - Cryptographic posture evidence", styles["Heading1"]),
               Paragraph(html.escape(report["executive_summary"]["overall_classification"]), styles["BodyText"]),
               Paragraph("Complete evidence follows. Null means unknown/unassessed. Unicode is preserved as JSON escapes.", styles["BodyText"]),
               Spacer(1, 12)]
    evidence = json.dumps(report, indent=2, default=str, ensure_ascii=True)
    for line in evidence.splitlines():
        # Bounded paragraphs avoid page-sized layout failures for hex buffers.
        for chunk in textwrap.wrap(line, width=105, replace_whitespace=False, drop_whitespace=False) or [""]:
            content.append(Paragraph(html.escape(chunk, quote=True).replace(" ", "&#160;") or "&#160;", code))
    document.build(content)
    return buffer.getvalue()


def generate_suricata_rules(evaluated_sessions):
    """Review-only, endpoint/port-scoped alert rules using basic Suricata syntax.

    These alert on subsequent matching flows, not on the original cryptographic
    defect. No drop/block action, direction inference or unverified TLS keyword.
    Validate against the target Suricata version with `suricata -T -S rules.rules`.
    """
    lines = ["# SecureMailScope review-only flow alerts; no blocking rules.",
             "# These match endpoint conversations, not exploitation or TLS weaknesses.",
             "# Review scope and run suricata -T with your configuration before use."]
    seen = set()
    sid = 1000000
    for session in evaluated_sessions:
        if session.get("status") not in ("critical", "high", "elevated"):
            continue
        try:
            src = str(ipaddress.ip_address(session.get("src_ip")))
            dst = str(ipaddress.ip_address(session.get("dst_ip")))
            port = int(session.get("dst_port"))
            if not 1 <= port <= 65535:
                continue
        except (ValueError, TypeError):
            continue
        key = (src, dst, port)
        if key in seen:
            continue
        seen.add(key)
        lines.append(f'alert tcp {src} any -> {dst} {port} (msg:"SecureMailScope reviewed posture flow"; flow:established; sid:{sid}; rev:1;)')
        sid += 1
    if not seen:
        lines.append("# No observed weakness with a valid endpoint/port scope to export.")
    return "\n".join(lines) + "\n"


def _timestamp(value):
    try:
        if isinstance(value, (int, float)):
            moment = dt.datetime.fromtimestamp(value, dt.timezone.utc)
        elif isinstance(value, str):
            moment = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            if moment.tzinfo is None:
                return None
        else:
            return None
        return moment.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError, OSError):
        return None


def generate_stix_bundle(evaluated_sessions):
    """STIX observations/notes, never malicious IP indicators from weak crypto."""
    now = _now()
    identity_id = f"identity--{uuid.uuid4()}"
    objects = [{"type": "identity", "spec_version": "2.1", "id": identity_id,
                "created": now, "modified": now, "name": "SecureMailScope passive analysis",
                "identity_class": "system"}]
    addresses = {}
    namespace = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
    for session in evaluated_sessions:
        refs = []
        for field in ("src_ip", "dst_ip"):
            try:
                address = ipaddress.ip_address(session.get(field))
            except (ValueError, TypeError):
                continue
            value = str(address)
            kind = "ipv4-addr" if address.version == 4 else "ipv6-addr"
            if value not in addresses:
                identifier = f"{kind}--{uuid.uuid5(namespace, json.dumps({'value': value}, sort_keys=True, separators=(',', ':')))}"
                addresses[value] = identifier
                objects.append({"type": kind, "spec_version": "2.1", "id": identifier, "value": value})
            refs.append(addresses[value])
        refs = list(dict.fromkeys(refs))
        first, last = _timestamp(session.get("start_time")), _timestamp(session.get("end_time"))
        if refs and first and last and dt.datetime.fromisoformat(last.replace("Z", "+00:00")) >= dt.datetime.fromisoformat(first.replace("Z", "+00:00")):
            observation_id = f"observed-data--{uuid.uuid4()}"
            objects.append({"type": "observed-data", "spec_version": "2.1", "id": observation_id,
                            "created": now, "modified": now, "created_by_ref": identity_id,
                            "first_observed": first, "last_observed": last, "number_observed": 1,
                            "object_refs": refs})
            refs = [observation_id]
        objects.append({"type": "note", "spec_version": "2.1", "id": f"note--{uuid.uuid4()}",
                        "created": now, "modified": now, "created_by_ref": identity_id,
                        "abstract": "Scoped cryptographic posture observation; no malicious-actor attribution",
                        "content": json.dumps({"limitations": REPORT_LIMITATIONS, "session": session}, default=str),
                        "object_refs": refs or [identity_id]})
    return json.dumps({"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}, indent=2)
