# Splunk Security Analysis Queries (Honeypot Filtered)
Generated: 2025-07-14

## Overview
These queries filter out honeypot IPs ending with: 102, 88, 96, 86, 91, 98, 101, 10, 108, 6, 77, 78, 79, 80, 83, 84, 87, 89, 93, 97, 94, 95

## Honeypot Filter Macro
Add this macro to all queries to exclude honeypot IPs:
```spl
| regex src.ip!="\.*(102|88|96|86|91|98|101|10|108|6|77|78|79|80|83|84|87|89|93|97|94|95)$"
| regex dst.ip!="\.*(102|88|96|86|91|98|101|10|108|6|77|78|79|80|83|84|87|89|93|97|94|95)$"
```

---

## 1. Critical Security Events & Attacks (Filtered)
**Purpose**: Find all critical security events, excluding honeypot traffic

```spl
index=main sourcetype=syslog (severity>=4 OR "CRITICAL" OR "HIGH" OR "ATTACK" OR "EXPLOIT" OR "alert") 
| rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<src_ip>[^\"]+)\"" 
| rex field=_raw "\"dst\":\s*{\s*\"ip\":\s*\"(?<dst_ip>[^\"]+)\"" 
| regex src_ip!="\.*(102|88|96|86|91|98|101|10|108|6|77|78|79|80|83|84|87|89|93|97|94|95)$" 
| regex dst_ip!="\.*(102|88|96|86|91|98|101|10|108|6|77|78|79|80|83|84|87|89|93|97|94|95)$" 
| stats count by src_ip, dst_ip, s_msg, att_ck 
| sort -count
```

## 2. CVE Exploitation Attempts (Filtered)
**Purpose**: Detect CVE exploits targeting real assets only

```spl
index=main sourcetype=syslog (CVE-* OR "ETERNALBLUE" OR "WannaCry" OR "Unimplemented Trans2") 
| rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<src_ip>[^\"]+)\"" 
| rex field=_raw "\"dst\":\s*{\s*\"ip\":\s*\"(?<dst_ip>[^\"]+)\"" 
| rex field=_raw "\"s_msg\":\s*\"(?<alert_msg>[^\"]+)\"" 
| regex src_ip!="\.*(102|88|96|86|91|98|101|10|108|6|77|78|79|80|83|84|87|89|93|97|94|95)$" 
| regex dst_ip!="\.*(102|88|96|86|91|98|101|10|108|6|77|78|79|80|83|84|87|89|93|97|94|95)$" 
| table _time, src_ip, dst_ip, alert_msg, CVE* 
| sort -_time
```

## 3. Top Threat Actors (Filtered)
**Purpose**: Identify real attackers, not honeypot interactions

```spl
index=main sourcetype=syslog ("ATTACK" OR "SUSPICIOUS" OR s_pr>=3) 
| rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<attacker_ip>[^\"]+)\"" 
| rex field=_raw "\"dst\":\s*{\s*\"ip\":\s*\"(?<target_ip>[^\"]+)\"" 
| regex attacker_ip!="\.*(102|88|96|86|91|98|101|10|108|6|77|78|79|80|83|84|87|89|93|97|94|95)$" 
| regex target_ip!="\.*(102|88|96|86|91|98|101|10|108|6|77|78|79|80|83|84|87|89|93|97|94|95)$" 
| stats count as attack_count by attacker_ip 
| sort -attack_count 
| head 20
```

## 4. DGA Domain Detection (Filtered)
**Purpose**: Find C2 communications from non-honeypot sources

```spl
index=main sourcetype=syslog ("dga" OR "sophosxl.net" OR cat="dga") 
| rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<src_ip>[^\"]+)\"" 
| rex field=_raw "\"dst\".*?\"dns\":\s*\"(?<suspicious_domain>[^\"]+)\"" 
| regex src_ip!="\.*(102|88|96|86|91|98|101|10|108|6|77|78|79|80|83|84|87|89|93|97|94|95)$" 
| stats count by suspicious_domain, src_ip 
| where count > 5 
| sort -count
```

## 5. Reconnaissance Activity (Filtered)
**Purpose**: Detect real reconnaissance, not honeypot monitoring

```spl
index=main sourcetype=syslog ("ip_checkers" OR "api.ipify.org" OR "ip-api.com" OR "api.bigdatacloud.net") 
| rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<recon_ip>[^\"]+)\"" 
| rex field=_raw "\"dst\".*?\"dns\":\s*\"(?<service>[^\"]+)\"" 
| regex recon_ip!="\.*(102|88|96|86|91|98|101|10|108|6|77|78|79|80|83|84|87|89|93|97|94|95)$" 
| stats dc(service) as unique_services, values(service) as services by recon_ip 
| where unique_services > 2
```

## 6. MITRE ATT&CK Techniques (Filtered)
**Purpose**: Map real attacks to MITRE framework

```spl
index=main sourcetype=syslog att_ck=* 
| rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<src_ip>[^\"]+)\"" 
| rex field=_raw "\"dst\":\s*{\s*\"ip\":\s*\"(?<dst_ip>[^\"]+)\"" 
| rex field=_raw "\"att_ck\":\s*\[\"(?<technique>[^\"]+)\"\]" 
| rex field=_raw "\"s_cls\":\s*\"(?<attack_class>[^\"]+)\"" 
| regex src_ip!="\.*(102|88|96|86|91|98|101|10|108|6|77|78|79|80|83|84|87|89|93|97|94|95)$" 
| regex dst_ip!="\.*(102|88|96|86|91|98|101|10|108|6|77|78|79|80|83|84|87|89|93|97|94|95)$" 
| stats count by technique, attack_class 
| sort -count
```

## 7. SMB Attack Patterns (Filtered)
**Purpose**: Detect SMB attacks on production systems

```spl
index=main sourcetype=syslog ("Anonymous SMB" OR "IPC share" OR "SMB" OR port=445) 
| rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<smb_attacker>[^\"]+)\"" 
| rex field=_raw "\"dst\":\s*{\s*\"ip\":\s*\"(?<target>[^\"]+)\"" 
| regex smb_attacker!="\.*(102|88|96|86|91|98|101|10|108|6|77|78|79|80|83|84|87|89|93|97|94|95)$" 
| regex target!="\.*(102|88|96|86|91|98|101|10|108|6|77|78|79|80|83|84|87|89|93|97|94|95)$" 
| stats count by smb_attacker, target 
| sort -count
```

## 8. Geographic Threat Analysis (Filtered)
**Purpose**: Real geographic threat distribution

```spl
index=main sourcetype=syslog 
| rex field=_raw "\"src\":[^}]+\"country\":\s*\"(?<country>[^\"]+)\"" 
| rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<src_ip>[^\"]+)\"" 
| rex field=_raw "\"dst\":\s*{\s*\"ip\":\s*\"(?<dst_ip>[^\"]+)\"" 
| rex field=_raw "\"cat\":\s*\"(?<category>[^\"]+)\"" 
| regex src_ip!="\.*(102|88|96|86|91|98|101|10|108|6|77|78|79|80|83|84|87|89|93|97|94|95)$" 
| regex dst_ip!="\.*(102|88|96|86|91|98|101|10|108|6|77|78|79|80|83|84|87|89|93|97|94|95)$" 
| stats count by country, category 
| sort -count 
| head 20
```

## 9. Advanced Combined Analysis (Filtered)
**Purpose**: Comprehensive security overview excluding honeypots

```spl
index=main sourcetype=syslog earliest=-24h
| rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<src_ip>[^\"]+)\"" 
| rex field=_raw "\"dst\":\s*{\s*\"ip\":\s*\"(?<dst_ip>[^\"]+)\"" 
| regex src_ip!="\.*(102|88|96|86|91|98|101|10|108|6|77|78|79|80|83|84|87|89|93|97|94|95)$" 
| regex dst_ip!="\.*(102|88|96|86|91|98|101|10|108|6|77|78|79|80|83|84|87|89|93|97|94|95)$"
| eval threat_level=case(
    match(_raw, "CVE-2017-0144"), "CRITICAL - EternalBlue",
    match(_raw, "CVE-2023-28771"), "CRITICAL - Zyxel RCE",
    match(_raw, "cobalt_strike"), "HIGH - C2 Framework",
    match(_raw, "sophosxl\.net"), "HIGH - DGA Domain",
    s_pr>=4, "HIGH - Alert",
    s_pr>=3, "MEDIUM - Warning",
    1=1, "LOW"
)
| rex field=_raw "\"s_msg\":\s*\"(?<message>[^\"]+)\"" 
| stats count by threat_level, src_ip, dst_ip, message 
| sort threat_level, -count
```

## 10. Real-time Dashboard (Production Assets Only)
**Purpose**: Monitor threats to actual production systems

```spl
index=main sourcetype=syslog earliest=-1h 
| rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<src_ip>[^\"]+)\"" 
| rex field=_raw "\"dst\":\s*{\s*\"ip\":\s*\"(?<dst_ip>[^\"]+)\"" 
| regex src_ip!="\.*(102|88|96|86|91|98|101|10|108|6|77|78|79|80|83|84|87|89|93|97|94|95)$" 
| regex dst_ip!="\.*(102|88|96|86|91|98|101|10|108|6|77|78|79|80|83|84|87|89|93|97|94|95)$"
| rex field=_raw "\"s_pr\":\s*(?<severity>\d+)" 
| rex field=_raw "\"cat\":\s*\"(?<category>[^\"]+)\"" 
| search (severity>=3 OR category IN ("dga", "exploit", "attack")) 
| timechart span=5m count by category
```

## 11. Threat Actor Profile (Non-Honeypot)
**Purpose**: Profile attackers targeting real systems

```spl
index=main sourcetype=syslog 
| rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<attacker>[^\"]+)\"" 
| rex field=_raw "\"dst\":\s*{\s*\"ip\":\s*\"(?<victim>[^\"]+)\"" 
| regex attacker!="\.*(102|88|96|86|91|98|101|10|108|6|77|78|79|80|83|84|87|89|93|97|94|95)$" 
| regex victim!="\.*(102|88|96|86|91|98|101|10|108|6|77|78|79|80|83|84|87|89|93|97|94|95)$"
| rex field=_raw "\"att_ck\":\s*\[\"(?<technique>[^\"]+)\"\]"
| rex field=_raw "\"s_pr\":\s*(?<priority>\d+)"
| stats dc(victim) as targets_count, dc(technique) as techniques_used, max(priority) as max_severity, count as total_events by attacker
| where total_events > 10
| eval threat_score = (targets_count * 10) + (techniques_used * 20) + (max_severity * 15) + (total_events / 10)
| sort -threat_score
| head 20
```

## 12. Critical Asset Targeting
**Purpose**: Find attacks specifically targeting non-honeypot production systems

```spl
index=main sourcetype=syslog 
| rex field=_raw "\"dst\":\s*{\s*\"ip\":\s*\"(?<target_ip>[^\"]+)\"" 
| regex target_ip!="\.*(102|88|96|86|91|98|101|10|108|6|77|78|79|80|83|84|87|89|93|97|94|95)$"
| rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<attacker>[^\"]+)\"" 
| rex field=_raw "\"s_msg\":\s*\"(?<alert>[^\"]+)\"" 
| rex field=_raw "\"s_pr\":\s*(?<severity>\d+)"
| search severity >= 3
| stats dc(attacker) as unique_attackers, values(alert) as alerts, max(severity) as max_severity, count as attack_count by target_ip
| where attack_count > 5
| sort -attack_count
```

## Helper Query: Verify Honeypot Filter
**Purpose**: Confirm honeypot IPs are being filtered correctly

```spl
index=main sourcetype=syslog earliest=-1h
| rex field=_raw "\"dst\":\s*{\s*\"ip\":\s*\"(?<ip>[^\"]+)\"" 
| eval is_honeypot=if(match(ip, "\.*(102|88|96|86|91|98|101|10|108|6|77|78|79|80|83|84|87|89|93|97|94|95)$"), "YES", "NO")
| stats count by is_honeypot
```

## Notes
- All queries now filter out IPs ending with honeypot suffixes
- This provides cleaner data focusing on real production threats
- Adjust the regex pattern if honeypot IP patterns change
- Consider saving the honeypot filter as a Splunk macro for easier maintenance