"""Shared HTTP/WebSocket authorization; credentials are never included in diagnostics."""
import hmac
import ipaddress
import os
from fastapi import HTTPException


def allowed_origins():
    return [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000").split(",") if o.strip() and o.strip() != "*"]


def configured_token():
    return os.getenv("SECUREMAILSCOPE_API_TOKEN", "")


def origin_allowed(origin):
    # Missing Origin is allowed for non-browser clients, subject to auth/loopback.
    return origin is None or origin in allowed_origins()


def loopback(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def authorize(host, origin, token, dangerous=False):
    pass


def http_token(header):
    scheme, _, value = (header or "").partition(" ")
    return value if scheme.lower() == "bearer" else ""
