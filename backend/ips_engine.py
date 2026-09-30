"""Explicit host-INPUT response. Rule presence never establishes capture-scope mitigation."""
import hashlib
import ipaddress
import os
import shutil
import subprocess
import threading
from datetime import datetime, timezone

STATUS_RECOMMENDED = "RECOMMENDED"
STATUS_DRY_RUN = "DRY_RUN"
STATUS_EXECUTING = "EXECUTING"
STATUS_EXECUTED = "EXECUTED"
STATUS_VERIFIED = "VERIFIED"
STATUS_FAILED = "FAILED"
STATUS_LOGGED_ONLY = "LOGGED_ONLY"
IPS_DRY_RUN_DEFAULT = os.getenv("IPS_DRY_RUN", "1").strip().lower() not in ("0", "false", "no")
_lock = threading.Lock()


def _validate_ip(value):
    try:
        return isinstance(value, str) and "%" not in value and bool(ipaddress.ip_address(value))
    except ValueError:
        return False


def _run(command):
    return subprocess.run(command, capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)


def _respond(ip_address, dry_run=None, rollback=False):
    outcome = {"status": STATUS_FAILED, "ip": ip_address, "dry_run": True,
               "scope": "current_host_network_namespace_input", "executed": False,
               "verified": False, "rule_present": None, "is_mitigated": False,
               "timestamp": datetime.now(timezone.utc).isoformat(), "evidence": []}
    if not _validate_ip(ip_address):
        return {**outcome, "message": "Invalid IPv4/IPv6 address"}
    ip = ipaddress.ip_address(ip_address)
    outcome["ip"] = str(ip)
    if ip.is_unspecified or ip.is_multicast or ip.is_loopback:
        return {**outcome, "message": "Unspecified, multicast and loopback targets are not accepted"}
    effective_dry_run = IPS_DRY_RUN_DEFAULT if dry_run is None else bool(dry_run)
    if effective_dry_run:
        return {**outcome, "status": STATUS_DRY_RUN, "message": "Validated target; no firewall commands executed"}
    # Independent server opt-in is required even for a caller explicitly passing dry_run=False.
    if os.getenv("ENABLE_ACTIVE_RESPONSE", "0") != "1":
        return {**outcome, "message": "Active response is not enabled"}
    outcome["dry_run"] = False
    if os.name != "posix":
        return {**outcome, "message": "Active response is available only for Linux iptables; this platform is unsupported"}
    binary = shutil.which("ip6tables" if ip.version == 6 else "iptables")
    if not binary:
        return {**outcome, "message": "Firewall executable unavailable"}
    tag = "SecureMailScope-" + hashlib.sha256(str(ip).encode()).hexdigest()[:20]
    spec = ["-s", str(ip), "-m", "comment", "--comment", tag, "-j", "DROP"]
    outcome["rule_id"] = tag
    outcome["rollback_supported"] = True
    def check():
        result = _run([binary, "-w", "3", "-C", "INPUT", *spec])
        outcome["evidence"].append({"operation": "query_exact_managed_rule", "returncode": result.returncode})
        if result.returncode not in (0, 1):
            raise RuntimeError("Firewall query failed")
        return result.returncode == 0
    try:
        with _lock:
            present = check()
            if rollback and not present:
                return {**outcome, "status": "ROLLED_BACK", "rule_present": False, "message": "Managed rule already absent"}
            if not rollback and present:
                return {**outcome, "status": STATUS_EXECUTED, "rule_present": True,
                        "idempotent": True, "message": "Managed rule exists; effective protection is not verified"}
            command = [binary, "-w", "3", "-D" if rollback else "-I", "INPUT"]
            if not rollback:
                command.append("1")
            result = _run([*command, *spec])
            outcome["evidence"].append({"operation": "delete" if rollback else "insert", "returncode": result.returncode})
            if result.returncode:
                return {**outcome, "message": "Firewall command failed; no mitigation claim"}
            outcome["executed"] = True
            outcome["rule_present"] = check()  # Independent state read, not the write exit status.
            if rollback:
                outcome["status"] = "ROLLED_BACK" if not outcome["rule_present"] else STATUS_FAILED
                outcome["message"] = "Managed rule removal independently queried"
            else:
                outcome["status"] = STATUS_EXECUTED
                outcome["message"] = "Write executed; rule presence queried. Remote-flow protection and policy effectiveness are not verified"
            return outcome
    except (OSError, subprocess.SubprocessError, RuntimeError):
        return {**outcome, "message": "Firewall command or verification failed; inspect host policy before retrying"}


def block_ip(ip_address, reason="Explicit operator response", dry_run=None):
    return _respond(ip_address, dry_run=dry_run)


def rollback_ip(ip_address, dry_run=None):
    return _respond(ip_address, dry_run=dry_run, rollback=True)
