"""Explicit SOC notifications. SMTP acceptance is not proof of delivery."""
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import parseaddr
import ipaddress
import json
import os
from pathlib import Path
import smtplib
import ssl

SENT = "SMTP_ACCEPTED"  # Legacy symbol retained, with truthful wire status.
FAILED = "FAILED"
LOGGED_ONLY = "LOGGED_ONLY"
NOT_CONFIGURED = "NOT_CONFIGURED"
ERROR = "ERROR"


def _address(value):
    if not value or "\r" in value or "\n" in value:
        raise ValueError("Invalid mailbox")
    _, address = parseaddr(value)
    if address != value or address.count("@") != 1 or any(c.isspace() for c in address):
        raise ValueError("Use a plain mailbox address")
    return address


def dispatch_alert(ip_address, threat_info, pdf_path=None, ips_result=None):
    try:
        ip = str(ipaddress.ip_address(ip_address))
        if not isinstance(threat_info, dict):
            raise ValueError("Invalid threat data")
        risk_factors = threat_info.get("risk_factors") or []
        remediations = threat_info.get("remediations") or []
        if not isinstance(risk_factors, list) or not isinstance(remediations, list):
            raise ValueError("Invalid finding lists")
        body = json.dumps({"subject": "Security posture findings requiring review", "ip": ip,
                           "time": datetime.now(timezone.utc).isoformat(),
                           "risk_factors": risk_factors[:100], "remediations": remediations[:100],
                           "response": ips_result or {"status": "NOT_ATTEMPTED"}}, default=str)
        if len(body) > 65536:
            raise ValueError("Alert too large")
        host = os.getenv("SMTP_HOST", "").strip()
        if not host:
            logged = _write_local_log(ip, body)
            return {"status": LOGGED_ONLY if logged else NOT_CONFIGURED, "logged": logged,
                    "accepted": False, "delivered": None, "message": "SMTP not configured"}
        if any(c.isspace() for c in host) or any(c in host for c in "\r\n"):
            raise ValueError("Invalid SMTP host")
        sender = _address(os.getenv("SMTP_FROM", ""))
        recipients = [_address(s.strip()) for s in os.getenv("SMTP_TO", "").split(",")]
        if len(recipients) > 100:
            raise ValueError("Too many recipients")
        mode = os.getenv("SMTP_TLS_MODE", "starttls").lower()
        if mode not in ("starttls", "implicit"):
            raise ValueError("SMTP_TLS_MODE must be starttls or implicit")
        port = int(os.getenv("SMTP_PORT", "465" if mode == "implicit" else "587"))
        if not 1 <= port <= 65535:
            raise ValueError("Invalid SMTP port")
        user, password = os.getenv("SMTP_USER", ""), os.getenv("SMTP_PASS", "")
        if bool(user) != bool(password):
            raise ValueError("Incomplete SMTP credentials")
        msg = EmailMessage()
        msg["Subject"] = f"[POSTURE REVIEW] SecureMailScope: {ip}"
        msg["From"], msg["To"] = sender, ", ".join(recipients)
        msg.set_content(body)
        if pdf_path:
            attachment = Path(pdf_path)
            if attachment.stat().st_size > 10 * 1024 * 1024:
                raise ValueError("Attachment too large")
            content = attachment.read_bytes()
            if not content.startswith(b"%PDF"):
                raise ValueError("Attachment is not PDF")
            msg.add_attachment(content, maintype="application", subtype="pdf", filename="assessment.pdf")
        context = ssl.create_default_context(cafile=os.getenv("SMTP_CA_FILE") or None)
        transport = smtplib.SMTP_SSL(host, port, timeout=10, context=context) if mode == "implicit" else smtplib.SMTP(host, port, timeout=10)
        with transport as smtp:
            smtp.ehlo()
            if mode == "starttls":
                smtp.starttls(context=context)
                smtp.ehlo()
            if user:
                smtp.login(user, password)
            refused = smtp.send_message(msg, from_addr=sender, to_addrs=recipients)
        refused_count = len(refused or {})
        accepted_count = len(recipients) - refused_count
        return {"status": SENT if not refused_count else "PARTIALLY_ACCEPTED" if accepted_count else FAILED,
                "accepted": accepted_count > 0, "accepted_count": accepted_count, "refused_count": refused_count,
                "delivered": None, "logged": False, "message": "SMTP server response recorded; delivery is not confirmed"}
    except (ValueError, TypeError, OSError, smtplib.SMTPException):
        # Exception strings may contain credentials or server responses; do not expose them.
        logged = _write_local_log(ip_address, body) if "body" in locals() else False
        return {"status": FAILED, "accepted": False, "delivered": None, "logged": logged,
                "message": "Alert validation or SMTP transmission failed"}


def _write_local_log(ip_address, body):
    try:
        path = Path(os.getenv("SOC_LOG_PATH", str(Path(__file__).with_name("soc_incidents.log"))))
        with path.open("a", encoding="utf-8") as target:
            target.write(json.dumps({"ip": ip_address, "body": body}) + "\n")
        return True
    except OSError:
        return False
