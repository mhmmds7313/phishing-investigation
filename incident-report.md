# Incident Report: VIP Recovery Phishing Campaign

**Report ID:** IR-2025-001  
**Date of Incident:** May 27, 2025  
**Date of Analysis:** September 2025  
**Analyst:** Mohammad Akib Shaikh  
**Severity:** High  
**Status:** Closed - Analysis Complete

---

## Executive Summary

A phishing email was delivered to a user containing a malicious RAR archive disguised as a business invoice. When extracted and executed, the embedded executable established persistence on the victim machine, beaconed to external infrastructure for geolocation data, and exfiltrated system information to an attacker-controlled email address using the "VIP Recovery" malware family.

The attacker used a compromised legitimate domain (`uyumelektrik.com`) to send the initial email, making it appear trustworthy. The malware used Telegram's API as a command-and-control channel, blending malicious traffic with legitimate HTTPS activity.

---

## Attack Timeline

| Time (UTC) | Event |
|------------|-------|
| 07:14:35 | Phishing email sent from compromised domain `uyumelektrik.com` |
| 19:32:31 | Malware executes, checks external IP via `checkip.dyndns.org` |
| 19:32:31 | Queries `reallyfreegeoip.org` for geolocation data |
| 19:32:34 | Beacons to `api.telegram.org` (C2 channel) |
| 19:32:40 | Exfiltrates data via SMTP to `mail.testeremarketim.com` |
| 19:32:48 | Data exfiltration email sent to `phinametics247@gmail.com` |

**Time from execution to exfiltration: 17 seconds.**

---

## Initial Access

### Email Analysis

The phishing email used the following characteristics:

| Header | Value | Analysis |
|--------|-------|----------|
| From | `=?UTF-8?B?IlR1cmFuIETEsE5DIg==?=` | Base64-encoded display name. Decodes to "Turan DİNÇ" — a fake persona. |
| Subject | `KABLO` | Turkish for "cable." Designed to look like a business inquiry. |
| Received | `from uyumelektrik.com [198.55.98.69]` | Sender IP belongs to a compromised legitimate domain. |
| Message-ID | `<20250527001435.3CCCD0212B127193@uyumelektrik.com>` | Domain matches the From header — consistent with compromised infrastructure, not spoofed. |

### Social Engineering Tactics

- **Business context lure:** The subject and filename impersonate a Turkish electrical company requesting a price quote for 2000 units.
- **Legitimate sender domain:** `uyumelektrik.com` is a real company. The attacker likely compromised their mail server.
- **File extension spoofing:** The attachment ends in `.r01` (a RAR multi-part extension) instead of `.rar` or `.exe`, hoping the user won't recognize it as executable content.

---

## Malware Analysis

### Attachment: RAR Archive

| Property | Value |
|----------|-------|
| SHA256 | `263f18680b864de7c8d5edd7622f07606205201976c755dd7fa98c80a8a770d4` |
| Size | 696,751 bytes |
| Type | RAR archive, v4, Win32 |

### Payload: Executable

| Property | Value |
|----------|-------|
| SHA256 | `aaf37584883937059e00508a1dfe72df4148efef238b4e86038902f968f220c1` |
| Size | 794,624 bytes |
| Type | PE32 executable, .NET assembly |
| Persistence | `C:\Users\[username]\AppData\Roaming\gCmiVoeYUJc.exe` |

The malware is a .NET executable that establishes persistence by copying itself to the user's AppData\Roaming folder with a randomized filename (`gCmiVoeYUJc.exe`). This is a common technique to evade detection and survive reboots.

---

## Command and Control

The malware used multiple external services to gather system information and maintain communication:

| Domain | Purpose | MITRE Technique |
|--------|---------|-----------------|
| `checkip.dyndns.org` | Determine victim's public IP | T1016 - System Network Configuration Discovery |
| `reallyfreegeoip.org` | Geolocate victim IP | T1614 - System Location Discovery |
| `api.telegram.org` | C2 beacon | T1102 - Web Service (Telegram abused as C2) |
| `mail.testeremarketim.com` | Data exfiltration via SMTP | T1048 - Exfiltration Over Alternative Protocol |

**Notable evasion:** Using Telegram's API as a C2 channel is effective because Telegram traffic is encrypted, widely allowed on corporate networks, and blends in with legitimate user activity.

---

## Indicators of Compromise (IOCs)

### File Hashes
- `263f18680b864de7c8d5edd7622f07606205201976c755dd7fa98c80a8a770d4` (RAR archive)
- `aaf37584883937059e00508a1dfe72df4148efef238b4e86038902f968f220c1` (EXE payload)

### Network Indicators
- `198.55.98.69` (sender IP)
- `132.226.247.73` (checkip.dyndns.org resolution)
- `104.21.64.1` (reallyfreegeoip.org resolution)
- `149.154.167.220` (api.telegram.org)
- `5.2.84.41` (mail.testeremarketim.com SMTP)
- `checkip.dyndns.org`
- `reallyfreegeoip.org`
- `api.telegram.org`
- `mail.testeremarketim.com`
- `uyumelektrik.com` (compromised sender)

### Email Indicators
- `info@testeremarketim.com` (attacker exfil address)
- `phinametics247@gmail.com` (attacker collection address)
- Display name: `Turan DİNÇ`

### File System Indicators
- `C:\Users\[username]\AppData\Roaming\gCmiVoeYUJc.exe`

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 |
| Execution | User Execution: Malicious File | T1204.002 |
| Persistence | Boot or Logon Autostart Execution | T1547 |
| Discovery | System Network Configuration Discovery | T1016 |
| Discovery | System Location Discovery | T1614 |
| Command and Control | Web Service | T1102 |
| Exfiltration | Exfiltration Over Alternative Protocol | T1048 |

---

## Detection Recommendations

### SIEM Detection Rules

1. **Email gateway rule:** Alert on RAR archives with `.r01` extensions from external senders.
2. **Network rule:** Alert on HTTPS traffic to `api.telegram.org` from non-browser processes.
3. **Endpoint rule:** Alert on executable creation in `AppData\Roaming` with randomized filenames.
4. **Process rule:** Alert when `checkip.dyndns.org` or `reallyfreegeoip.org` are contacted by non-standard processes.

### Hunting Queries (KQL - Microsoft Sentinel)

```kusto
// Detect executable creation in AppData\Roaming
DeviceFileEvents
| where FolderPath has "AppData\\Roaming"
| where FileName endswith ".exe"
| where InitiatingProcessFileName !in ("explorer.exe", "setup.exe")
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName
