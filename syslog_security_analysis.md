# Splunk Syslog Security Analysis Report

**Date**: 2025-07-09  
**Data Source**: Splunk Syslog (UDP Port 514)  
**Analysis Period**: Last 24 hours

## Executive Summary

This report analyzes security events collected via syslog from host 10.213.10.5 (ptnad-aio-1751981640). The analysis reveals active exploitation attempts, reconnaissance activities, and potential command & control communications.

## Critical Security Findings

### 1. Active Exploitation Attempts

| CVE/Attack Type | Description | Count | Severity |
|-----------------|-------------|-------|----------|
| CVE-2017-0144 | EternalBlue/WannaCry (SMB vulnerability) | 2 | Critical |
| CVE-2023-28771 | Zyxel ZyWALL/USG OS command execution | 2 | Critical |
| SMB Attacks | Anonymous SMB connect to IPC share | 4 | High |
| SSH Brute Force | Paramiko SSH python library attacks | 1 | Medium |

### 2. Primary Threat Actor Analysis

**Main Attacker IP**: 103.145.125.10
- **Organization**: PT Transportasi Jakarta, Indonesia
- **Total Events**: 232 (87% of all security events)
- **ASN**: 139447
- **Geolocation**: Jakarta, Indonesia (-6.175, 106.8286)

### 3. Threat Categories Distribution

| Category | Event Count | Description |
|----------|-------------|-------------|
| DGA Domains | 319 | Domain Generation Algorithm - potential C2 |
| IP Checkers | 279 | External IP verification services |
| Cobalt Strike | 1 | Command & Control framework indicator |
| TOR Relays | 1 | Anonymization service usage |

### 4. Suspicious Domains and Services

#### Top Targeted Domains:
1. **api.bigdatacloud.net** (157 connections) - IP geolocation service
2. **sophosxl.net subdomains** (201 connections) - Suspected C2 infrastructure
   - 4.sophosxl.net
   - http.00.h.sophosxl.net
   - http.00.a.sophosxl.net
3. **ip-api.com** (39 connections) - IP lookup service
4. **api.ipify.org** (57 connections) - External IP checker

#### Suspicious DGA Patterns:
- `gs11.dkitrxmdwoqruvsi.net` - Identified as Murofet malware
- `static.v2kyu1kjr.com` - Potential C2 domain
- `popc-dir-eu.pc8oeqtzy9.com` - Suspicious pattern

## MITRE ATT&CK Framework Mapping

| Tactic | Technique | Description | Event Count |
|--------|-----------|-------------|-------------|
| TA0001 | T1190 | Exploit Public-Facing Application | 14 |
| TA0008 | T1021.002 | Remote Services: SMB/Windows Admin Shares | 12 |
| TA0007 | T1083 | File and Directory Discovery | 3 |
| TA0011 | T1071.001 | Application Layer Protocol: Web Protocols | 2 |
| TA0008 | T1021.004 | Remote Services: SSH | 1 |

## Recommended Actions

### Immediate Response Actions

1. **Network Blocking**
   ```
   # Block primary threat actor
   iptables -A INPUT -s 103.145.125.10 -j DROP
   
   # Block suspicious domains
   *.sophosxl.net
   *.dkitrxmdwoqruvsi.net
   *.v2kyu1kjr.com
   *.pc8oeqtzy9.com
   ```

2. **Vulnerability Patching**
   - Apply MS17-010 patch for EternalBlue vulnerability
   - Update Zyxel devices to patch CVE-2023-28771
   - Disable SMBv1 protocol
   - Restrict anonymous SMB access

3. **Security Monitoring**
   - Enable enhanced logging for SMB connections
   - Monitor for lateral movement from potentially compromised systems
   - Set up alerts for connections to identified C2 domains

### Detection Rules for Splunk

```spl
# Rule 1: Detect EternalBlue exploitation attempts
index=main sourcetype=syslog "CVE-2017-0144" OR "ETERNALBLUE"
| stats count by src_ip, dst_ip
| where count > 1

# Rule 2: Detect DGA domain communications
index=main sourcetype=syslog 
| rex field=_raw "\"cat\":\s*\"dga\""
| rex field=_raw "\"dst\".*?\"dns\":\s*\"(?<dga_domain>[^\"]+)\""
| stats count by dga_domain, src_ip

# Rule 3: Detect multiple IP checker queries (reconnaissance)
index=main sourcetype=syslog 
| rex field=_raw "\"cat\":\s*\"ip_checkers\""
| rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<src_ip>[^\"]+)\""
| stats dc(dst_dns) as unique_checkers by src_ip
| where unique_checkers > 2

# Rule 4: Alert on known attack patterns
index=main sourcetype=syslog 
| search "ATTACK" OR "SUSPICIOUS" OR "alert"
| table _time, src_ip, alert_msg, attack_technique
```

### Example Splunk Queries to Investigate Threats

#### 1. View All EternalBlue/WannaCry Attack Attempts
```spl
sourcetype=syslog "ETERNALBLUE" OR "WannaCry" OR "CVE-2017-0144" OR "Unimplemented Trans2"
| table _time, src.ip, dst.ip, s_msg, att_ck
| sort -_time
```

#### 2. Track Primary Threat Actor Activity Timeline
```spl
sourcetype=syslog "103.145.125.10"
| rex field=_raw "\"type\":\s*\"(?<event_type>[^\"]+)\""
| rex field=_raw "\"s_msg\":\s*\"(?<alert_msg>[^\"]+)\""
| table _time, event_type, alert_msg, dst.dns, dst.port
| sort _time
```

#### 3. Investigate Zyxel Device Exploitation
```spl
sourcetype=syslog "CVE-2023-28771" OR "Zyxel ZyWALL"
| rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<attacker_ip>[^\"]+)\""
| rex field=_raw "\"dst\":\s*{\s*\"ip\":\s*\"(?<target_ip>[^\"]+)\""
| table _time, attacker_ip, target_ip, s_msg, payload
| sort -_time
```

#### 4. Analyze DGA Domain Communications
```spl
sourcetype=syslog "sophosxl.net"
| rex field=_raw "\"dst\":\s*{[^}]*\"dns\":\s*\"(?<c2_domain>[^\"]+sophosxl[^\"]+)\""
| stats count by c2_domain, src.ip
| eval threat_level=case(count>10, "HIGH", count>5, "MEDIUM", 1=1, "LOW")
| sort -count
```

#### 5. Monitor Anonymous SMB Attack Patterns
```spl
sourcetype=syslog "Anonymous SMB" OR "IPC share"
| rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<attacker>[^\"]+)\""
| rex field=_raw "\"dst\":\s*{\s*\"ip\":\s*\"(?<victim>[^\"]+)\""
| timechart span=1h count by attacker
```

#### 6. Real-time Threat Dashboard Query
```spl
sourcetype=syslog earliest=-24h
| rex field=_raw "\"s_pr\":\s*(?<severity>\d+)"
| rex field=_raw "\"cat\":\s*\"(?<category>[^\"]+)\""
| search severity>=3 OR category="dga" OR "ATTACK" OR "SUSPICIOUS"
| stats count by category, severity
| eval risk_score=severity*count
| sort -risk_score
```

#### 7. IP Reputation Check Activity
```spl
sourcetype=syslog ("api.ipify.org" OR "ip-api.com" OR "api.bigdatacloud.net")
| rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<source_ip>[^\"]+)\""
| stats dc(dst.dns) as unique_services, values(dst.dns) as services, count as queries by source_ip
| where unique_services > 2
| sort -queries
```

#### 8. Cobalt Strike Indicators
```spl
sourcetype=syslog ("cobalt_strike" OR "beacon" OR "ESC-auto-cobalt")
| rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<c2_server>[^\"]+)\""
| rex field=_raw "\"dst\":\s*{\s*\"ip\":\s*\"(?<compromised_host>[^\"]+)\""
| table _time, c2_server, compromised_host, cat, rpt
```

#### 9. SSH Brute Force Detection
```spl
sourcetype=syslog "Paramiko" OR "SSH python"
| rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<ssh_attacker>[^\"]+)\""
| rex field=_raw "\"dst\":\s*{\s*\"port\":\s*(?<ssh_port>\d+)"
| stats count by ssh_attacker, dst.ip, ssh_port
| where ssh_port=22
```

#### 10. Combined Threat Intelligence View
```spl
sourcetype=syslog earliest=-24h
| rex field=_raw "\"att_ck\":\s*\[\"(?<mitre_technique>[^\"]+)\"\]"
| rex field=_raw "\"s_cls\":\s*\"(?<attack_class>[^\"]+)\""
| rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<src_ip>[^\"]+)\""
| stats dc(mitre_technique) as techniques_used, 
        values(mitre_technique) as mitre_techniques,
        values(attack_class) as attack_types,
        count as total_events by src_ip
| eval threat_score=techniques_used*10 + if(total_events>100, 50, total_events/2)
| sort -threat_score
| head 20
```

#### 11. Payload Analysis for Exploitation Attempts
```spl
sourcetype=syslog payload=*
| rex field=_raw "\"payload\":\s*\"(?<encoded_payload>[^\"]+)\""
| eval decoded_payload=urldecode(encoded_payload)
| rex field=_raw "\"s_msg\":\s*\"(?<alert_description>[^\"]+)\""
| table _time, src.ip, dst.ip, alert_description, decoded_payload
| sort -_time
```

#### 12. Geographic Threat Distribution
```spl
sourcetype=syslog 
| rex field=_raw "\"src\":[^}]+\"country\":\s*\"(?<src_country>[^\"]+)\""
| rex field=_raw "\"cat\":\s*\"(?<threat_category>[^\"]+)\""
| stats count by src_country, threat_category
| sort -count
```

### Long-term Security Improvements

1. **Network Segmentation**
   - Isolate critical systems from direct internet access
   - Implement DMZ for public-facing services

2. **Enhanced Monitoring**
   - Deploy EDR solutions on endpoints
   - Implement network traffic analysis (NTA)
   - Enable full packet capture for forensics

3. **Access Control**
   - Implement least privilege access
   - Enable multi-factor authentication
   - Regular access reviews and cleanup

## Indicators of Compromise (IoCs)

### IP Addresses
- 103.145.125.10 (Primary attacker)
- 103.167.26.74
- 103.167.27.74
- 14.188.36.70

### Domains
- *.sophosxl.net
- gs11.dkitrxmdwoqruvsi.net
- static.v2kyu1kjr.com
- popc-dir-eu.pc8oeqtzy9.com

### User Agents/Tools
- Paramiko SSH library
- Potential Cobalt Strike beacon

## Conclusion

The analysis reveals an active threat actor conducting reconnaissance and exploitation attempts against the network. The combination of vulnerability scanning, DGA domain usage, and exploitation attempts suggests a sophisticated attack campaign. Immediate action is required to block the threat actor and patch vulnerable systems.

---
*Report generated from Splunk syslog data analysis*  
*Total events analyzed: 267*