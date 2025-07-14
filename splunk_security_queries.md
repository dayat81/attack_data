# Splunk Security Analysis Queries
Generated: 2025-07-14 15:37:04

## Overview
These queries are designed to extract security insights from Splunk syslog data, similar to the analysis in syslog_security_analysis.md.

## How to Use
1. Access Splunk Web UI at http://10.213.10.3:8000/en-GB/app/search
2. Copy and paste each query into the search bar
3. Adjust time range as needed (default: last 24 hours)
4. Save useful queries as reports or alerts

## Honeypot IP Filter
To exclude honeypot IPs (ending with: 102, 88, 96, 86, 91, 98, 101, 10, 108, 6, 77, 78, 79, 80, 83, 84, 87, 89, 93, 97, 94, 95), add this to any query:
```spl
| regex src_ip!="\.*(102|88|96|86|91|98|101|10|108|6|77|78|79|80|83|84|87|89|93|97|94|95)$"
| regex dst_ip!="\.*(102|88|96|86|91|98|101|10|108|6|77|78|79|80|83|84|87|89|93|97|94|95)$"
```

---

## 1. Critical Security Events & Attacks
**Purpose**: Find all critical security events, attacks, and exploits

```spl
index=main sourcetype=syslog (severity>=4 OR "CRITICAL" OR "HIGH" OR "ATTACK" OR "EXPLOIT" OR "alert") | stats count by src, dst, s_msg, att_ck | sort -count
```

## 2. CVE Exploitation Attempts
**Purpose**: Detect specific CVE exploitation attempts (EternalBlue, Zyxel, etc.)

```spl
index=main sourcetype=syslog (CVE-* OR "ETERNALBLUE" OR "WannaCry" OR "Unimplemented Trans2") | rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<src_ip>[^\"]+)\"" | rex field=_raw "\"s_msg\":\s*\"(?<alert_msg>[^\"]+)\"" | table _time, src_ip, alert_msg, CVE* | sort -_time
```

## 3. Top Threat Actors
**Purpose**: Identify top attacking IPs with event counts

```spl
index=main sourcetype=syslog ("ATTACK" OR "SUSPICIOUS" OR s_pr>=3) | rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<attacker_ip>[^\"]+)\"" | stats count as attack_count by attacker_ip | sort -attack_count | head 20
```

## 4. DGA Domain Detection
**Purpose**: Find Domain Generation Algorithm (DGA) and C2 domains

```spl
index=main sourcetype=syslog ("dga" OR "sophosxl.net" OR cat="dga") | rex field=_raw "\"dst\".*?\"dns\":\s*\"(?<suspicious_domain>[^\"]+)\"" | stats count by suspicious_domain | where count > 5 | sort -count
```

## 5. Reconnaissance Activity
**Purpose**: Detect IP checking and reconnaissance services

```spl
index=main sourcetype=syslog ("ip_checkers" OR "api.ipify.org" OR "ip-api.com" OR "api.bigdatacloud.net") | rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<recon_ip>[^\"]+)\"" | rex field=_raw "\"dst\".*?\"dns\":\s*\"(?<service>[^\"]+)\"" | stats dc(service) as unique_services, values(service) as services by recon_ip | where unique_services > 2
```

## 6. MITRE ATT&CK Techniques
**Purpose**: Map events to MITRE ATT&CK framework

```spl
index=main sourcetype=syslog att_ck=* | rex field=_raw "\"att_ck\":\s*\[\"(?<technique>[^\"]+)\"\]" | rex field=_raw "\"s_cls\":\s*\"(?<attack_class>[^\"]+)\"" | stats count by technique, attack_class | sort -count
```

## 7. SMB Attack Patterns
**Purpose**: Detect SMB/anonymous share attacks

```spl
index=main sourcetype=syslog ("Anonymous SMB" OR "IPC share" OR "SMB" OR port=445) | rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<smb_attacker>[^\"]+)\"" | rex field=_raw "\"dst\":\s*{\s*\"ip\":\s*\"(?<target>[^\"]+)\"" | stats count by smb_attacker, target | sort -count
```

## 8. Geographic Threat Analysis
**Purpose**: Analyze threats by country of origin

```spl
index=main sourcetype=syslog | rex field=_raw "\"src\":[^}]+\"country\":\s*\"(?<country>[^\"]+)\"" | rex field=_raw "\"cat\":\s*\"(?<category>[^\"]+)\"" | stats count by country, category | sort -count | head 20
```

## 9. Cobalt Strike Detection
**Purpose**: Detect Cobalt Strike beacons and C2

```spl
index=main sourcetype=syslog ("cobalt_strike" OR "beacon" OR "CS-" OR cat="cobalt_strike") | rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<c2_server>[^\"]+)\"" | rex field=_raw "\"dst\":\s*{\s*\"ip\":\s*\"(?<victim>[^\"]+)\"" | table _time, c2_server, victim, _raw
```

## 10. SSH Brute Force
**Purpose**: Detect SSH brute force attempts

```spl
index=main sourcetype=syslog ("Paramiko" OR "SSH" OR dst.port=22) | rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<ssh_attacker>[^\"]+)\"" | stats count as attempts by ssh_attacker | where attempts > 5 | sort -attempts
```

## 11. Payload Analysis
**Purpose**: Extract and analyze attack payloads

```spl
index=main sourcetype=syslog payload=* | rex field=_raw "\"payload\":\s*\"(?<encoded_payload>[^\"]+)\"" | rex field=_raw "\"s_msg\":\s*\"(?<description>[^\"]+)\"" | eval decoded=urldecode(encoded_payload) | table _time, description, decoded | sort -_time
```

## 12. Real-time Threat Dashboard
**Purpose**: Combined threat overview for dashboard

```spl
index=main sourcetype=syslog earliest=-1h | rex field=_raw "\"s_pr\":\s*(?<severity>\d+)" | rex field=_raw "\"cat\":\s*\"(?<category>[^\"]+)\"" | search (severity>=3 OR category IN ("dga", "exploit", "attack")) | timechart span=5m count by category
```

## 13. Indonesian Threat Actor (103.145.125.10)
**Purpose**: Track specific threat actor from Jakarta

```spl
index=main sourcetype=syslog "103.145.125.10" | rex field=_raw "\"type\":\s*\"(?<event_type>[^\"]+)\"" | rex field=_raw "\"s_msg\":\s*\"(?<message>[^\"]+)\"" | table _time, event_type, message | sort _time
```

## 14. Suspicious Domain Pattern Analysis
**Purpose**: Analyze patterns in suspicious domains

```spl
index=main sourcetype=syslog | rex field=_raw "\"dst\".*?\"dns\":\s*\"(?<domain>[^\"]+)\"" | eval is_suspicious=if(match(domain, "(sophosxl\.net|dkitrxmdwoqruvsi\.net|v2kyu1kjr\.com|pc8oeqtzy9\.com)"), 1, 0) | where is_suspicious=1 | stats count by domain | sort -count
```

## 15. Security Event Timeline
**Purpose**: Create timeline of all security events

```spl
index=main sourcetype=syslog (s_pr>=3 OR "ATTACK" OR "CVE-") | bin _time span=1h | stats count by _time | eval severity=case(count>100, "CRITICAL", count>50, "HIGH", count>20, "MEDIUM", 1=1, "LOW")
```

## Bonus: Combined Security Analysis

**Purpose**: Comprehensive security overview combining multiple detection methods

```spl
index=main sourcetype=syslog earliest=-24h
| eval threat_level=case(
    match(_raw, "CVE-2017-0144"), "CRITICAL - EternalBlue",
    match(_raw, "CVE-2023-28771"), "CRITICAL - Zyxel RCE",
    match(_raw, "cobalt_strike"), "HIGH - C2 Framework",
    match(_raw, "sophosxl\.net"), "HIGH - DGA Domain",
    s_pr>=4, "HIGH - Alert",
    s_pr>=3, "MEDIUM - Warning",
    1=1, "LOW"
)
| rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<src_ip>[^\"]+)\"" 
| rex field=_raw "\"s_msg\":\s*\"(?<message>[^\"]+)\"" 
| stats count by threat_level, src_ip, message 
| sort threat_level, -count
```

## Alert Recommendations

Based on the analysis patterns, consider creating these alerts:

1. **Critical CVE Exploitation**: Alert when CVE-2017-0144 or CVE-2023-28771 detected
2. **High Volume Attacker**: Alert when single IP generates >100 events/hour  
3. **DGA Domain Communication**: Alert on connections to known DGA domains
4. **Geographic Anomaly**: Alert on attacks from new countries
5. **Cobalt Strike Beacon**: Alert on any Cobalt Strike indicators

---

*Note: These queries are based on the syslog data structure observed in the security analysis report.*
