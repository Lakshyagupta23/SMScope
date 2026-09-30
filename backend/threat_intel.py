"""Opt-in reputation enrichment. Matches never establish actor identity or compromise.

Default is offline/disabled. Local feeds contain exact IP/JA3 observations with
provenance and expiry. The only online integration is VirusTotal IP reputation.
"""
import copy
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import threading
import time
import urllib.parse
import urllib.request

_cache = {}
_lock = threading.Lock()
_next_request = 0.0
_MAX_CACHE = 512


def _enabled(name):
    return os.getenv(name, "").lower() in ("1", "true", "yes")


def _now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _number(name, default, minimum):
    try:
        return max(minimum, float(os.getenv(name, str(default))))
    except ValueError:
        return default


def _local_feed():
    path = os.getenv("SECUREMAILSCOPE_CTI_FEED")
    if not path:
        return [], "not_queried", "No local provenance-bearing feed configured."
    try:
        with open(path, "r", encoding="utf-8") as source:
            raw = source.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("feed too large")
        feed = json.loads(raw)
        if not isinstance(feed, dict) or feed.get("schema_version") != 1 or not isinstance(feed.get("indicators"), list):
            raise ValueError("invalid feed schema")
        valid = []
        now = dt.datetime.now(dt.timezone.utc)
        for entry in feed["indicators"]:
            if not isinstance(entry, dict) or not all(entry.get(k) for k in ("type", "value", "source", "retrieved_at", "expires_at")):
                raise ValueError("feed indicator lacks provenance/expiry")
            retrieved = dt.datetime.fromisoformat(entry["retrieved_at"].replace("Z", "+00:00"))
            expires = dt.datetime.fromisoformat(entry["expires_at"].replace("Z", "+00:00"))
            if retrieved.tzinfo is None or expires.tzinfo is None or retrieved > now or expires <= retrieved:
                raise ValueError("invalid provenance timestamps")
            if expires <= now:
                continue
            value = entry["value"]
            if entry["type"] == "ip":
                value = str(ipaddress.ip_address(value))  # prefixes/ranges are refused
            elif entry["type"] == "ja3" and re.fullmatch(r"[0-9a-fA-F]{32}", value):
                value = value.lower()
            else:
                raise ValueError("only exact IP or canonical JA3 indicators are supported")
            valid.append({**entry, "value": value})
        return valid, "available", None
    except Exception as exc:
        return [], "unavailable", f"Local feed unavailable: {type(exc).__name__}: {exc}"


def _local_match(kind, value):
    if not _enabled("SECUREMAILSCOPE_CTI_ENABLED"):
        return None
    entries, _, _ = _local_feed()
    return next((copy.deepcopy(e) for e in entries if e["type"] == kind and e["value"] == value), None)


def check_ip_local(ip):
    try:
        return _local_match("ip", str(ipaddress.ip_address(ip)))
    except ValueError:
        return None


def check_ja3_local(ja3_hash):
    return _local_match("ja3", str(ja3_hash).lower())


def check_virustotal_ip(ip):
    global _next_request
    result = {"source": "VirusTotal", "indicator_type": "ip", "ip": ip,
              "status": "not_queried", "queried_at": None, "cached": False}
    if not (_enabled("SECUREMAILSCOPE_CTI_ENABLED") and _enabled("SECUREMAILSCOPE_CTI_NETWORK_ENABLED")):
        result["reason"] = "Online enrichment is disabled."
        return result
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        result["reason"] = "Invalid IP address."
        return result
    if not address.is_global or address.is_multicast or address.is_unspecified:
        result["reason"] = "Non-public address is not disclosed to external providers."
        return result
    key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not key:
        result.update(status="unavailable", reason="VirusTotal API key is not configured.")
        return result
    cache_key = (str(address), hashlib.sha256(key.encode()).hexdigest())
    monotonic = time.monotonic()
    with _lock:
        cached = _cache.get(cache_key)
        if cached and monotonic < cached[0]:
            return {**copy.deepcopy(cached[1]), "cached": True}
        if monotonic < _next_request:
            result.update(status="unavailable", reason="Local request rate limit; lookup not sent.")
            return result
        _next_request = monotonic + _number("SECUREMAILSCOPE_CTI_MIN_INTERVAL", 15, 1)
    try:
        url = "https://www.virustotal.com/api/v3/ip_addresses/" + urllib.parse.quote(str(address), safe="")
        request = urllib.request.Request(url, headers={"x-apikey": key})
        with urllib.request.urlopen(request, timeout=3) as response:
            raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("response too large")
        data = json.loads(raw).get("data", {})
        if data.get("type") != "ip_address" or ipaddress.ip_address(data.get("id", "")) != address:
            raise ValueError("provider returned a different indicator")
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats")
        if not isinstance(stats, dict) or not stats or any(type(v) is not int or v < 0 for v in stats.values()):
            raise ValueError("provider analysis statistics unavailable")
        votes = stats.get("malicious", 0)
        result.update(status="match" if votes else "no_match", queried_at=_now(),
                      malicious_votes=votes, total_engines=sum(stats.values()),
                      provider_analysis_time=attrs.get("last_analysis_date"),
                      confidence="uncalibrated provider votes",
                      threat=f"Provider reputation observation: {votes} malicious votes; not proof of compromise.")
    except Exception as exc:
        result.update(status="unavailable", reason=f"Provider lookup failed: {type(exc).__name__}")
    ttl = _number("SECUREMAILSCOPE_CTI_CACHE_TTL", 3600, 1) if result["status"] != "unavailable" else 30
    with _lock:
        if len(_cache) >= _MAX_CACHE:
            _cache.pop(next(iter(_cache)))
        _cache[cache_key] = (time.monotonic() + ttl, copy.deepcopy(result))
    return result


def check_virustotal_ja3(ja3_hash):
    return {"status": "not_queried", "source": "VirusTotal", "hash": ja3_hash,
            "reason": "No verified JA3 relationship API is implemented; generic file searches are not used."}


def enrich_session(session):
    result = {"findings": [], "lookups": [], "is_threat_actor": False,
              "is_known_malicious": None, "has_reputation_match": False,
              "vt_available": False, "status": "not_queried",
              "limitations": "Reputation matches are context only, not actor attribution or proof of malicious traffic."}
    if not _enabled("SECUREMAILSCOPE_CTI_ENABLED"):
        result["reason"] = "CTI disabled by default; no addresses or fingerprints queried."
        return result
    entries, feed_status, reason = _local_feed()
    result["local_feed"] = {"status": feed_status, "reason": reason, "valid_indicators": len(entries)}
    candidates = []
    for role in ("src_ip", "dst_ip"):
        value = session.get(role)
        if not value:
            continue
        try:
            value = str(ipaddress.ip_address(value))
        except ValueError:
            continue
        candidates.append(("ip", value, role))
        lookup = {**check_virustotal_ip(value), "endpoint_role": role}
        result["lookups"].append(lookup)
        if lookup["status"] in ("match", "no_match"):
            result["vt_available"] = True
        if lookup["status"] == "match":
            result["findings"].append(lookup)
    ja3 = session.get("ja3")
    if isinstance(ja3, dict) and re.fullmatch(r"[0-9a-fA-F]{32}", str(ja3.get("hash", ""))):
        candidates.append(("ja3", ja3["hash"].lower(), "client_fingerprint"))
    for kind, value, role in candidates:
        if feed_status != "available":
            continue
        matches = [e for e in entries if e["type"] == kind and e["value"] == value]
        result["lookups"].append({"source": "local_feed", "status": "match" if matches else "no_match",
                                  "indicator_type": kind, "value": value, "endpoint_role": role})
        for entry in matches:
            result["findings"].append({**entry, "indicator_type": kind, "endpoint_role": role,
                                      "ip" if kind == "ip" else "hash": value, "status": "match",
                                      "threat": "Exact reputation-feed match; independent review required."})
    states = [lookup["status"] for lookup in result["lookups"]]
    result["has_reputation_match"] = bool(result["findings"])
    if result["findings"]:
        result["status"] = "match"
    elif "unavailable" in states or feed_status == "unavailable":
        result["status"] = "unavailable"
    elif "no_match" in states:
        result["status"] = "no_match"
    result["coverage_incomplete"] = feed_status != "available" or any(s in ("unavailable", "not_queried") for s in states)
    return result
