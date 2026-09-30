"""Optional, bounded plaintext rule matching. No TLS decryption or MIME extraction."""
RULESET_VERSION = "securemailscope.plaintext.v2"
RULES_SOURCE = r'''
rule PE_ReflectiveLoader_Strings {
    meta:
        description = "PE header plus reflective-loader strings; review required"
    strings:
        $loader = "ReflectiveLoader" ascii
        $beacon = "beacon.dll" ascii nocase
        $dos = "This program cannot be run in DOS mode" ascii
    condition:
        uint16(0) == 0x5a4d and $dos and $loader and $beacon
}
rule Ransom_Demand_Language {
    strings:
        $encrypted = "All your files have been encrypted" ascii nocase
        $demand = "pay the ransom" ascii nocase
        $currency = "bitcoin" ascii nocase fullword
    condition:
        all of them
}
rule PowerShell_Encoded_Execution_Strings {
    strings:
        $host = "powershell.exe" ascii nocase fullword
        $decode = "FromBase64String" ascii nocase fullword
        $execute = "Invoke-Expression" ascii nocase fullword
        $iex = "IEX" ascii nocase fullword
    condition:
        $host and $decode and ($execute or $iex)
}
'''
compiled_rules = None
YARA_AVAILABLE = False
_unavailable_reason = "yara-python is not installed"
try:
    import yara
    YARA_AVAILABLE = True
    compiled_rules = yara.compile(source=RULES_SOURCE)
except Exception as exc:
    _unavailable_reason = f"YARA unavailable: {type(exc).__name__}"


def scan_plaintext(payload_bytes, *, plaintext_confirmed=False):
    result = {"status": "not_queried", "matches": [], "ruleset_version": RULESET_VERSION,
              "scanned_bytes": 0, "truncated": False,
              "limitations": "Exact rule matches require review; no malware-family attribution, TLS decryption, or MIME/attachment reconstruction."}
    if not plaintext_confirmed:
        result["reason"] = "Input is not confirmed plaintext; encrypted/unknown bytes are not scanned."
        return result
    if compiled_rules is None:
        result.update(status="unavailable", reason=_unavailable_reason)
        return result
    if not isinstance(payload_bytes, bytes) or not payload_bytes:
        result["reason"] = "No plaintext bytes available."
        return result
    bounded = payload_bytes[:1024 * 1024]
    result["truncated"] = len(payload_bytes) > len(bounded)
    try:
        result["matches"] = sorted({match.rule for match in compiled_rules.match(data=bounded, timeout=3)})
        result.update(status="match" if result["matches"] else "no_match", scanned_bytes=len(bounded))
    except Exception as exc:
        result.update(status="unavailable", reason=f"Rule scan failed: {type(exc).__name__}")
    return result


def scan_payload(payload_bytes, *, plaintext_confirmed=False):
    """Legacy list interface. Call scan_plaintext for explicit component status."""
    return scan_plaintext(payload_bytes, plaintext_confirmed=plaintext_confirmed)["matches"]
