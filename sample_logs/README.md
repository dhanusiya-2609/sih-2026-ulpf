# Sample Logs

All files in this directory are **synthetic** test data, generated for
prototype/demo purposes. They are **not** captured from any production
network or system, and all IPs used are from documentation ranges reserved
by RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) or private
ranges (`10.0.0.0/8`, `192.168.0.0/16`).

Each file intentionally includes at least one malformed / unparseable line
to demonstrate the framework's fallback and error-handling behavior (see
`AC-10`/`AC-11` in `docs/evaluation_checklist.md`).

| File | Simulated source | Format | Notes |
|---|---|---|---|
| `cisco_ios_router.log` | Cisco IOS router | Syslog (RFC3164) + Cisco `%FACILITY-SEVERITY-MNEMONIC` | ACL deny/permit, interface state, login failure, OSPF adjacency |
| `cisco_catalyst_switch.log` | Cisco Catalyst switch | Syslog + Cisco mnemonic | Interface flap, MAC flap, config change, one malformed line |
| `paloalto_firewall.log` | Palo Alto Networks firewall | Syslog-wrapped CEF | Traffic allow/deny, threat log, GlobalProtect VPN, admin login failure |
| `fortinet_fortigate.log` | Fortinet FortiGate firewall | Syslog-wrapped native `key=value` | Traffic policy, IPsec tunnel, admin login failure, one corrupted line |
| `linux_server.log` | Linux server | Syslog (sshd/systemd/kernel/sudo) + one JSON application log line | SSH auth failure/success, kernel interface events, sudo command, app-level JSON |

### Expected results when uploaded via Sources → Upload log files

The vendor and device type are **detected automatically from the log
content** (Cisco mnemonics, CEF/LEEF headers, FortiGate's `devid=FG.../
logid=`, Linux daemon tags) — you don't need to type them in first. Upload
any file above as-is and the created source will show the correct vendor.

Some lines (interface flap notices, config-change banners, MAC-flap
warnings) are expected to normalize with `status=partial` — the syslog
envelope and Cisco mnemonic are understood, but the message carries no
network 5-tuple or action, so the framework correctly reports partial
rather than overstating confidence. This is intended behavior, not a bug.
