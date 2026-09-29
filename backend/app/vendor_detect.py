"""
Vendor and device-type auto-detection from log *content*.

Why this exists: a Source only knows its vendor if a human typed it in. When
logs are uploaded in bulk (Sources -> Upload log files) nobody has typed
anything, so without detection every event would show vendor "Unknown".

Detection is deliberately conservative -- it only reports a vendor when a
distinctive, well-known signature is present, and returns None otherwise
(the caller then keeps "Unknown" rather than guessing):

  * CEF / LEEF headers carry the vendor name explicitly.
  * Cisco IOS/Catalyst/ASA syslog uses the %FACILITY-SEVERITY-MNEMONIC form.
  * FortiGate logs use devid=FG.../logid=/devname= key=value pairs.
  * Linux syslog is recognised by daemon tags (sshd, systemd, sudo, kernel, CRON).
"""
import re
from collections import Counter
from typing import Optional

UNKNOWN = "Unknown"

_CEF_VENDOR = re.compile(r"CEF:\d+\|([^|]*)\|")
_LEEF_VENDOR = re.compile(r"LEEF:[\d.]+\|([^|]*)\|")
_CISCO_MNEMONIC = re.compile(r"%[A-Z0-9_]+-\d-[A-Z0-9_]+:")
_FORTI = re.compile(r"\bdevid=FG|\bdevname=.*\blogid=|\blogid=\d+.*\btype=(traffic|event|utm)", re.S)
_LINUX_TAG = re.compile(r"\b(sshd|systemd|sudo|CRON|cron|kernel|login|su)(\[\d+\])?:")

# Canonical display names for vendors that show up in CEF/LEEF headers.
_CANONICAL = {
    "palo alto": "Palo Alto Networks",
    "fortinet": "Fortinet",
    "cisco": "Cisco",
    "check point": "Check Point",
    "juniper": "Juniper Networks",
    "arista": "Arista Networks",
    "sophos": "Sophos",
    "f5": "F5 Networks",
    "microsoft": "Microsoft",
    "trend micro": "Trend Micro",
    "imperva": "Imperva",
}

# Sensible default device type per vendor; refined by content/filename hints.
_DEFAULT_TYPE = {
    "Palo Alto Networks": "firewall",
    "Fortinet": "firewall",
    "Check Point": "firewall",
    "Sophos": "firewall",
    "Cisco": "network device",
    "Juniper Networks": "network device",
    "Arista Networks": "switch",
    "Linux": "server",
    "Microsoft": "server",
}

_SWITCH_HINTS = re.compile(r"SPANTREE|SW_MATM|PORTFAST|ETHCNT|PM-4|STORM_CONTROL|catalyst|switch", re.I)
_ROUTER_HINTS = re.compile(r"OSPF|BGP|EIGRP|IPACCESSLOG|router|rtr", re.I)


def _canonical(name: str) -> str:
    n = name.strip()
    low = n.lower()
    for key, canon in _CANONICAL.items():
        if key in low:
            return canon
    return n or UNKNOWN


def detect_vendor(raw_text: str) -> Optional[str]:
    """Best-effort vendor for ONE raw event; None if no confident signature."""
    if not raw_text:
        return None
    m = _CEF_VENDOR.search(raw_text) or _LEEF_VENDOR.search(raw_text)
    if m and m.group(1).strip():
        return _canonical(m.group(1))
    if _CISCO_MNEMONIC.search(raw_text):
        return "Cisco"
    if _FORTI.search(raw_text):
        return "Fortinet"
    if "PAN-OS" in raw_text or "Palo Alto" in raw_text:
        return "Palo Alto Networks"
    if _LINUX_TAG.search(raw_text):
        return "Linux"
    return None


def detect_vendor_for_lines(lines: list[str], sample: int = 200) -> Optional[str]:
    """Majority vote across the first `sample` non-empty lines of a file, so a
    single odd or corrupted line cannot change the answer."""
    votes = Counter()
    for line in lines[:sample]:
        v = detect_vendor(line)
        if v:
            votes[v] += 1
    return votes.most_common(1)[0][0] if votes else None


def guess_device_type(vendor: Optional[str], text_or_name: str = "") -> str:
    """Device type from vendor default, refined by mnemonics/filename hints
    (e.g. Cisco + SPANTREE/'catalyst' -> switch, Cisco + OSPF/'rtr' -> router)."""
    if not vendor or vendor == UNKNOWN:
        return "unknown"
    if vendor in ("Cisco", "Juniper Networks"):
        if _SWITCH_HINTS.search(text_or_name):
            return "switch"
        if _ROUTER_HINTS.search(text_or_name):
            return "router"
    return _DEFAULT_TYPE.get(vendor, "unknown")


def is_unknown(value: Optional[str]) -> bool:
    return value is None or value.strip() == "" or value.strip().lower().startswith("unknown")
