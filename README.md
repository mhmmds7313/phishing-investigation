# Phishing Investigation: VIP Recovery Campaign

I analyzed a real phishing sample to practice the kind of email triage an L1 SOC analyst does every day. The sample involved a malicious RAR archive disguised as a business invoice and a malware family that used Telegram as its command-and-control channel.

The full incident report is in [incident-report.md](incident-report.md).

---

## What Made This Sample Interesting

A Turkish-language email arrived from a compromised legitimate domain (uyumelektrik.com) with a subject line reading "KABLO" (Turkish for "cable"). The attachment was a RAR archive named to look like a price quote for 2000 electrical units. Inside was a .NET executable that established persistence in the user's AppData folder and began exfiltrating data within 17 seconds of execution.

The attacker didn't spoof the sender. They compromised a real company's mail server and used it, which means the email passed SPF and DKIM checks.

---

## What I Did

| Area | Work |
|------|------|
| Email headers | Decoded base64 display name, traced sender IP, examined Message-ID |
| Social engineering | Identified the business-context lure and file extension spoofing (.r01) |
| Malware behavior | Reviewed persistence mechanism and execution chain |
| C2 infrastructure | Mapped the domains the malware contacted |
| IOC extraction | Compiled hashes, IPs, domains, email addresses, file paths |
| MITRE ATT&CK | Mapped each stage of the attack to its technique |
| Detection | Wrote SIEM rules and KQL hunting queries |

---

## Key Findings

**The email was not spoofed—it came from a compromised legitimate domain.** SPF and DKIM passed because the sender was real. Detection has to go beyond email authentication.

**The attachment used a multi-part RAR extension (.r01)** instead of .rar or .exe, hoping the user wouldn't recognize it as executable content.

**The malware used Telegram's API for C2.** Encrypted, widely allowed, blends in with normal traffic.

**From execution to exfiltration was 17 seconds.** No human analyst could respond in time. Only automated detection works here.

---

## Repository Contents

| File | Contents |
|------|----------|
| [incident-report.md](incident-report.md) | Full report: timeline, IOCs, MITRE mapping, detection queries |
| [source/source-data.md](source/source-data.md) | Raw source data from malware-traffic-analysis.net |

---

## Detection Queries

Two KQL queries written for Microsoft Sentinel based on this attack:

```kusto
DeviceFileEvents
| where FolderPath has "AppData\\Roaming"
| where FileName endswith ".exe"
| where InitiatingProcessFileName !in ("explorer.exe", "setup.exe")
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName
