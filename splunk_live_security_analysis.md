# Splunk Live Security Analysis Guide

**Generated**: 2025-07-14  
**Splunk Instance**: http://10.213.10.3:8000 (localhost:8000)  
**Data Source**: Syslog UDP Port 514

## Quick Start - Finding Security Insights

### Step 1: Access Splunk
1. Open browser to: http://localhost:8000/en-GB/app/search
2. Login with: admin / admin123
3. Set time range to "Last 24 hours" or as needed

### Step 2: Run Key Security Queries

Copy and paste these queries directly into Splunk search bar:

#### 🔴 Find Critical Threats (Similar to Original Report)

**1. Active Exploitation Attempts (CVEs)**
```spl
index=main sourcetype=syslog ("CVE-2017-0144" OR "CVE-2023-28771" OR "ETERNALBLUE" OR "Zyxel") | rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<attacker>[^\"]+)\"" | rex field=_raw "\"s_msg\":\s*\"(?<description>[^\"]+)\"" | table _time, attacker, description, CVE* | sort -_time
```

**2. Primary Threat Actor Analysis (103.145.125.10)**
```spl
index=main sourcetype=syslog "103.145.125.10" | rex field=_raw "\"type\":\s*\"(?<event_type>[^\"]+)\"" | rex field=_raw "\"cat\":\s*\"(?<category>[^\"]+)\"" | rex field=_raw "\"s_msg\":\s*\"(?<alert>[^\"]+)\"" | stats count by event_type, category, alert | sort -count
```

**3. DGA/C2 Domains (sophosxl.net pattern)**
```spl
index=main sourcetype=syslog ("sophosxl.net" OR "dga" OR cat="dga") | rex field=_raw "\"dst\".*?\"dns\":\s*\"(?<c2_domain>[^\"]+)\"" | rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<infected_host>[^\"]+)\"" | stats count by c2_domain, infected_host | where match(c2_domain, "sophosxl|dkitrxmdwoqruvsi|v2kyu1kjr|pc8oeqtzy9")
```

#### 🟡 Reconnaissance & Lateral Movement

**4. IP Checker Services (Recon Indicator)**
```spl
index=main sourcetype=syslog ("api.ipify.org" OR "ip-api.com" OR "api.bigdatacloud.net" OR cat="ip_checkers") | rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<source>[^\"]+)\"" | rex field=_raw "\"dst\".*?\"dns\":\s*\"(?<service>[^\"]+)\"" | stats dc(service) as recon_services, values(service) as services_used, count by source | where recon_services > 2
```

**5. SMB/Network Attacks**
```spl
index=main sourcetype=syslog ("Anonymous SMB" OR "IPC share" OR "445" OR "139") | rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<attacker>[^\"]+)\"" | rex field=_raw "\"dst\":\s*{\s*\"ip\":\s*\"(?<target>[^\"]+)\"" | timechart span=1h count by attacker
```

#### 🟢 Threat Intelligence & Analysis

**6. MITRE ATT&CK Mapping**
```spl
index=main sourcetype=syslog att_ck=* | rex field=_raw "\"att_ck\":\s*\[\"(?<technique>[^\"]+)\"\]" | rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<source>[^\"]+)\"" | stats count by technique, source | eval tactic=case(match(technique, "T1190"), "Initial Access", match(technique, "T1021"), "Lateral Movement", match(technique, "T1083"), "Discovery", match(technique, "T1071"), "C2", 1=1, "Other") | sort -count
```

**7. Geographic Threat Distribution**
```spl
index=main sourcetype=syslog | rex field=_raw "\"src\":[^}]+\"country\":\s*\"(?<country>[^\"]+)\"" | rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<ip>[^\"]+)\"" | rex field=_raw "\"s_pr\":\s*(?<priority>\d+)" | search priority>=3 | stats dc(ip) as unique_attackers, count as total_attacks by country | sort -total_attacks
```

### Step 3: Create Real-time Dashboard

**Combined Security Overview Dashboard Query:**
```spl
index=main sourcetype=syslog earliest=-24h 
| rex field=_raw "\"s_pr\":\s*(?<severity>\d+)" 
| rex field=_raw "\"cat\":\s*\"(?<category>[^\"]+)\"" 
| rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<src_ip>[^\"]+)\"" 
| eval threat_score=case(
    match(_raw, "CVE-2017-0144|CVE-2023-28771"), 100,
    category="cobalt_strike", 90,
    category="dga", 80,
    category="exploit", 70,
    severity>=4, 60,
    severity>=3, 40,
    1=1, 10
)
| stats sum(threat_score) as risk_score, dc(src_ip) as unique_sources, count as events by category 
| eval risk_level=case(risk_score>1000, "CRITICAL", risk_score>500, "HIGH", risk_score>100, "MEDIUM", 1=1, "LOW")
| sort -risk_score
```

## Key Findings to Look For

Based on the original analysis, search for these patterns:

### 1. **Critical CVEs**
- CVE-2017-0144 (EternalBlue/WannaCry)
- CVE-2023-28771 (Zyxel OS Command Execution)

### 2. **Suspicious Domains**
- *.sophosxl.net (C2 infrastructure)
- *.dkitrxmdwoqruvsi.net (Murofet malware)
- *.v2kyu1kjr.com
- *.pc8oeqtzy9.com

### 3. **Key Threat Actors**
- 103.145.125.10 (Jakarta, Indonesia - Primary)
- 103.167.26.74
- 103.167.27.74
- 14.188.36.70

### 4. **Threat Categories**
- DGA Domains (300+ events expected)
- IP Checkers (200+ events expected)
- Cobalt Strike indicators
- TOR relay usage

## Advanced Analysis Queries

### Detect New Threats (Not in Original Report)
```spl
index=main sourcetype=syslog earliest=-24h latest=now 
| rex field=_raw "\"src\":\s*{\s*\"ip\":\s*\"(?<src_ip>[^\"]+)\"" 
| search NOT src_ip IN ("103.145.125.10", "103.167.26.74", "103.167.27.74", "14.188.36.70")
| rex field=_raw "\"s_pr\":\s*(?<priority>\d+)" 
| where priority >= 3
| stats count, values(s_msg) as alerts by src_ip 
| where count > 50
| sort -count
```

### Payload Decoder
```spl
index=main sourcetype=syslog payload=* 
| rex field=_raw "\"payload\":\s*\"(?<encoded>[^\"]+)\"" 
| eval decoded=urldecode(encoded) 
| rex field=decoded "(?<command>cmd\.exe|powershell|/bin/sh|/bin/bash)" 
| where isnotnull(command)
| table _time, src.ip, dst.ip, command, decoded
```

### Timeline Analysis
```spl
index=main sourcetype=syslog (s_pr>=3 OR "ATTACK" OR "CVE-") 
| bin _time span=1h 
| stats count as events, dc(src.ip) as unique_attackers, values(att_ck) as techniques by _time 
| eval hour=strftime(_time, "%Y-%m-%d %H:00")
| eval status=case(events>100, "🔴 CRITICAL", events>50, "🟡 HIGH", events>20, "🟠 MEDIUM", 1=1, "🟢 LOW")
| table hour, status, events, unique_attackers, techniques
```

## Creating Alerts

Based on findings, create these Splunk alerts:

1. **EternalBlue Exploitation**
   - Search: `index=main sourcetype=syslog "CVE-2017-0144"`
   - Trigger: Real-time
   - Action: Email security team

2. **New High-Volume Attacker**
   - Search: `index=main sourcetype=syslog | stats count by src.ip | where count > 100`
   - Trigger: Every hour
   - Action: Add to blocklist

3. **DGA Domain Communication**
   - Search: `index=main sourcetype=syslog cat="dga"`
   - Trigger: When count > 10 in 5 minutes
   - Action: Isolate endpoint

## Summary

This guide provides queries to find security insights similar to those in the original syslog_security_analysis.md report. Key areas to monitor:

1. **Exploitation attempts** (CVEs)
2. **C2 communications** (DGA domains)
3. **Reconnaissance** (IP checkers)
4. **Geographic anomalies**
5. **MITRE ATT&CK techniques**

Run these queries regularly to maintain security visibility and detect new threats.