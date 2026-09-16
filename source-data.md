# Source Data

## Sample Information
- **Source:** malware-traffic-analysis.net
- **Post:** 2025-05-27 (Tuesday) - VIP Recovery Infection from Email Attachment
- **URL:** https://www.malware-traffic-analysis.net/2025/05/27/index.html
- **Date of Incident:** May 27, 2025

## Email Headers

- **Received:** from uyumelektrik.com (unknown [198.55.98.69])
- **From:** =?UTF-8?B?IlR1cmFuIETEsE5DIg==?=
- **Subject:** KABLO
- **Date:** 27 May 2025 00:14:36 -0700
- **Message-ID:** <20250527001435.3CCCD0212B127193@uyumelektrik.com>
- **Attachment filename:** UYUM ELK.İNŞ Fiyat Talebi Hk... 2000 adet 2025007586311133_250527132701.r01

## Malicious Files

### RAR Archive
- **SHA256:** 263f18680b864de7c8d5edd7622f07606205201976c755dd7fa98c80a8a770d4
- **Size:** 696,751 bytes
- **File name:** UYUM ELK.İNŞ Fiyat Talebi Hk... 2000 adet 2025007586311133_250527132701.r01
- **Type:** RAR archive data, v4, os: Win32

### Executable Payload
- **SHA256:** aaf37584883937059e00508a1dfe72df4148efef238b4e86038902f968f220c1
- **Size:** 794,624 bytes
- **File name:** UYUM ELK.İNŞ Fiyat Talebi Hk... 2000 adet 2025007586311133_250527132701.exe
- **Type:** PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows
- **Persistence location:** C:\Users\[username]\AppData\Roaming\gCmiVoeYUJc.exe

## Infection Traffic

| Timestamp (UTC) | IP Address | Port | Domain | Info |
|-----------------|------------|------|--------|------|
| 2025-05-27 19:32:31 | 132.226.247.73 | 80 | checkip.dyndns.org | GET / HTTP/1.1 |
| 2025-05-27 19:32:31 | 104.21.64.1 | 443 | reallyfreegeoip.org | HTTPS traffic |
| 2025-05-27 19:32:34 | 149.154.167.220 | 443 | api.telegram.org | HTTPS traffic |
| 2025-05-27 19:32:40 | 5.2.84.41 | 587 | mail.testeremarketim.com | SMTP traffic |

## Data Exfiltration Email

- **From:** info@testeremarketim.com
- **To:** phinametics247@gmail.com
- **Date:** 27 May 2025 19:32:48 +0000
- **Subject:** Pc Name: user1 | / VIP Recovery \
