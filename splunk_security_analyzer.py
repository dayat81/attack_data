#!/usr/bin/env python3
"""
Splunk Security Analyzer with Anthropic LLM Integration
Fetches security events from Splunk and uses Claude to analyze patterns and generate insights
"""

import os
import sys
import json
import time
import argparse
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Any
import urllib3
from anthropic import Anthropic

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SplunkSecurityAnalyzer:
    def __init__(self, splunk_host: str, splunk_user: str, splunk_pass: str, anthropic_key: str):
        self.splunk_host = splunk_host
        self.splunk_user = splunk_user
        self.splunk_pass = splunk_pass
        self.anthropic = Anthropic(api_key=anthropic_key)
        self.session = requests.Session()
        self.session.auth = (splunk_user, splunk_pass)
        self.session.verify = False
        
    def search_splunk(self, query: str, earliest: str = "-24h", latest: str = "now") -> List[Dict]:
        """Execute a search query in Splunk and return results"""
        search_url = f"{self.splunk_host}/services/search/jobs"
        export_url = f"{self.splunk_host}/services/search/jobs/export"
        
        # Build the full query for display
        full_query = f"search {query} earliest={earliest} latest={latest}"
        
        search_params = {
            'search': f'search {query}',
            'earliest_time': earliest,
            'latest_time': latest,
            'output_mode': 'json'
        }
        
        print(f"Executing Splunk search: {query}")
        print(f"Full query: {full_query}")
        
        try:
            # Export search (streaming)
            response = self.session.post(export_url, data=search_params)
            response.raise_for_status()
            
            results = []
            for line in response.text.strip().split('\n'):
                if line:
                    try:
                        result = json.loads(line)
                        if 'result' in result:
                            results.append(result['result'])
                    except json.JSONDecodeError:
                        continue
                        
            print(f"Retrieved {len(results)} events from Splunk")
            return results
            
        except Exception as e:
            print(f"Error executing Splunk search: {str(e)}")
            return []
    
    def get_security_events(self, time_window: str = "-24h") -> Dict[str, Any]:
        """Fetch various security events from Splunk"""
        
        # Define queries for different security aspects
        queries = {
            "critical_alerts": 'sourcetype=syslog (severity>=4 OR "CRITICAL" OR "HIGH") | head 100',
            "new_attackers": 'sourcetype=syslog "ATTACK" | stats count by src_ip | sort -count | head 20',
            "exploitation_attempts": 'sourcetype=syslog ("CVE-" OR "exploit" OR "vulnerability") | head 50',
            "suspicious_domains": 'sourcetype=syslog ("dga" OR "c2" OR "cobalt_strike") | head 50',
            "attack_patterns": 'sourcetype=syslog att_ck=* | stats count by att_ck | sort -count | head 20',
            "recent_events": 'sourcetype=syslog earliest=-1h | head 100'
        }
        
        all_results = {}
        self.executed_queries = []  # Store queries for report
        
        for query_name, query in queries.items():
            print(f"\nFetching {query_name}...")
            # Use time_window for all queries except recent_events which has its own time range
            if query_name != "recent_events":
                results = self.search_splunk(query, earliest=time_window)
                self.executed_queries.append({
                    'name': query_name,
                    'query': f"index=main {query} earliest={time_window} latest=now"
                })
            else:
                results = self.search_splunk(query)
                self.executed_queries.append({
                    'name': query_name,
                    'query': f"index=main {query} latest=now"
                })
            all_results[query_name] = results
            
        return all_results
    
    def prepare_data_for_analysis(self, security_data: Dict[str, Any]) -> str:
        """Prepare security data for LLM analysis"""
        
        summary = "SPLUNK SECURITY DATA SUMMARY\n" + "="*50 + "\n\n"
        
        # Critical alerts summary
        if security_data.get("critical_alerts"):
            summary += "CRITICAL ALERTS (Sample):\n"
            for i, event in enumerate(security_data["critical_alerts"][:10]):
                summary += f"{i+1}. {event.get('_raw', '')[:200]}...\n"
            summary += f"\nTotal critical alerts: {len(security_data['critical_alerts'])}\n\n"
        
        # New attackers
        if security_data.get("new_attackers"):
            summary += "TOP ATTACKING IPs:\n"
            for event in security_data["new_attackers"][:10]:
                if '_raw' in event:
                    summary += f"- {event['_raw']}\n"
            summary += "\n"
        
        # Exploitation attempts
        if security_data.get("exploitation_attempts"):
            summary += "EXPLOITATION ATTEMPTS:\n"
            cves = set()
            for event in security_data["exploitation_attempts"]:
                raw = event.get('_raw', '')
                if 'CVE-' in raw:
                    import re
                    cve_matches = re.findall(r'CVE-\d{4}-\d+', raw)
                    cves.update(cve_matches)
            
            for cve in list(cves)[:10]:
                summary += f"- {cve}\n"
            summary += f"\nTotal exploitation events: {len(security_data['exploitation_attempts'])}\n\n"
        
        # Recent events sample
        if security_data.get("recent_events"):
            summary += "RECENT EVENTS (Last Hour Sample):\n"
            for i, event in enumerate(security_data["recent_events"][:5]):
                summary += f"{i+1}. {event.get('_raw', '')[:150]}...\n"
            summary += f"\nTotal recent events: {len(security_data['recent_events'])}\n"
        
        return summary
    
    def analyze_with_llm(self, data_summary: str) -> str:
        """Use Anthropic Claude to analyze security data"""
        
        prompt = f"""You are a cybersecurity analyst reviewing Splunk security logs. Analyze the following security data and provide:

1. **New Security Insights**: Identify any new threats, attack patterns, or security concerns that weren't in the previous report
2. **Trend Analysis**: Compare with the previous report dated 2025-07-09 and highlight changes
3. **Critical Findings**: List the most critical security issues requiring immediate attention
4. **Recommendations**: Provide specific, actionable recommendations

Previous report highlighted:
- Primary attacker: 103.145.125.10 (Jakarta, Indonesia)
- CVE-2017-0144 (EternalBlue) and CVE-2023-28771 (Zyxel) exploits
- DGA domains including sophosxl.net
- 267 total security events

Current data:
{data_summary}

Please provide a concise but comprehensive analysis focusing on what's NEW or CHANGED since the last report."""

        try:
            response = self.anthropic.messages.create(
                model="claude-3-sonnet-20240229",
                max_tokens=2000,
                temperature=0,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            return response.content[0].text
            
        except Exception as e:
            return f"Error analyzing with LLM: {str(e)}"
    
    def generate_report(self, analysis: str, time_window: str) -> str:
        """Generate the final security report"""
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Generate query verification section
        query_section = "\n## Splunk Queries Used (Copy to Verify)\n\n"
        query_section += "You can verify these results by running the following queries in Splunk:\n\n"
        
        for query_info in self.executed_queries:
            query_section += f"### {query_info['name'].replace('_', ' ').title()}\n"
            query_section += f"```spl\n{query_info['query']}\n```\n\n"
        
        # Add specific detection queries based on analysis
        query_section += "### Additional Detection Queries\n\n"
        
        # EternalBlue detection
        query_section += "#### Detect EternalBlue/WannaCry attacks\n"
        query_section += f"""```spl
index=main sourcetype=syslog ("CVE-2017-0144" OR "ETERNALBLUE") earliest={time_window} latest=now | rex field=_raw "\\"src\\":\\s*{{\\s*\\"ip\\":\\s*\\"(?<src_ip>[^\\"]+)\\"" | rex field=_raw "\\"dst\\":\\s*{{\\s*\\"ip\\":\\s*\\"(?<dst_ip>[^\\"]+)\\"" | stats count by src_ip, dst_ip | where count > 1
```\n\n"""
        
        # DGA domain detection
        query_section += "#### Detect DGA domain communications\n"
        query_section += f"""```spl
index=main sourcetype=syslog "dga" earliest={time_window} latest=now | rex field=_raw "\\"dst\\".*?\\"dns\\":\\s*\\"(?<dga_domain>[^\\"]+)\\"" | stats count by dga_domain | head 20
```\n\n"""
        
        # Attack source analysis
        query_section += "#### Analyze attack sources by country\n"
        query_section += f"""```spl
index=main sourcetype=syslog earliest={time_window} latest=now | rex field=_raw "\\"src\\":[^}}]+\\"country\\":\\s*\\"(?<src_country>[^\\"]+)\\"" | rex field=_raw "\\"cat\\":\\s*\\"(?<threat_category>[^\\"]+)\\"" | stats count by src_country, threat_category | sort -count
```\n\n"""
        
        report = f"""# Splunk Security Analysis Update
**Generated**: {timestamp}
**Analysis Type**: Automated LLM-Enhanced Security Review

## Executive Summary
This report provides updated security insights based on the latest Splunk data, analyzed using Anthropic Claude AI.

---

{analysis}

---

{query_section}

## Automated Analysis Notes
- This analysis was generated using Anthropic Claude to identify patterns and insights
- Data source: Splunk syslog data from {self.splunk_host}
- Time window: {time_window} from {timestamp}
- Analysis includes comparison with previous report from 2025-07-09

## Next Steps
1. Review and validate the findings
2. Update security controls based on recommendations
3. Continue monitoring for identified threats
4. Schedule follow-up analysis
"""
        
        return report
    
    def run(self, output_file: str = None, time_window: str = "-24h"):
        """Main execution flow"""
        
        print("Starting Splunk Security Analysis...")
        print(f"Connecting to Splunk at {self.splunk_host}")
        print(f"Analyzing events from: {time_window}")
        
        # Fetch security data
        security_data = self.get_security_events(time_window)
        
        # Prepare data for analysis
        data_summary = self.prepare_data_for_analysis(security_data)
        
        print("\nAnalyzing data with Anthropic Claude...")
        # Analyze with LLM
        analysis = self.analyze_with_llm(data_summary)
        
        # Generate report
        report = self.generate_report(analysis, time_window)
        
        # Save or display report
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            print(f"\nReport saved to: {output_file}")
        else:
            print("\n" + "="*80)
            print(report)
            print("="*80)
        
        return report


def main():
    parser = argparse.ArgumentParser(description='Analyze Splunk security data with Anthropic LLM')
    parser.add_argument('--splunk-host', default='http://10.213.10.3:8000', 
                        help='Splunk host URL')
    parser.add_argument('--splunk-user', default='admin', 
                        help='Splunk username')
    parser.add_argument('--splunk-pass', default='admin123', 
                        help='Splunk password')
    parser.add_argument('--anthropic-key', required=True, 
                        help='Anthropic API key')
    parser.add_argument('--output', '-o', 
                        help='Output file for the report')
    parser.add_argument('--update-existing', action='store_true',
                        help='Update the existing syslog_security_analysis.md file')
    parser.add_argument('--time-window', '-t', default='-24h',
                        help='Time window for analysis (e.g., -24h, -7d, -1w, -30d)')
    parser.add_argument('--generate-queries-only', action='store_true',
                        help='Only generate Splunk queries without running analysis')
    
    args = parser.parse_args()
    
    # Handle query generation only mode
    if args.generate_queries_only:
        print("\n" + "="*80)
        print("SPLUNK SECURITY ANALYSIS QUERIES")
        print("="*80 + "\n")
        
        time_window = args.time_window
        
        queries = {
            "Critical Alerts": f'index=main sourcetype=syslog (severity>=4 OR "CRITICAL" OR "HIGH") earliest={time_window} latest=now | head 100',
            "Attack Sources": f'index=main sourcetype=syslog "ATTACK" earliest={time_window} latest=now | stats count by src_ip | sort -count | head 20',
            "Exploitation Attempts": f'index=main sourcetype=syslog ("CVE-" OR "exploit" OR "vulnerability") earliest={time_window} latest=now | head 50',
            "Suspicious Domains": f'index=main sourcetype=syslog ("dga" OR "c2" OR "cobalt_strike") earliest={time_window} latest=now | head 50',
            "MITRE ATT&CK Patterns": f'index=main sourcetype=syslog att_ck=* earliest={time_window} latest=now | stats count by att_ck | sort -count | head 20',
            "EternalBlue Detection": f'index=main sourcetype=syslog ("CVE-2017-0144" OR "ETERNALBLUE") earliest={time_window} latest=now | rex field=_raw "\\"src\\":\\s*{{\\s*\\"ip\\":\\s*\\"(?<src_ip>[^\\"]+)\\"" | rex field=_raw "\\"dst\\":\\s*{{\\s*\\"ip\\":\\s*\\"(?<dst_ip>[^\\"]+)\\"" | stats count by src_ip, dst_ip | where count > 1',
            "DGA Domains": f'index=main sourcetype=syslog "dga" earliest={time_window} latest=now | rex field=_raw "\\"dst\\".*?\\"dns\\":\\s*\\"(?<dga_domain>[^\\"]+)\\"" | stats count by dga_domain | head 20',
            "Geographic Distribution": f'index=main sourcetype=syslog earliest={time_window} latest=now | rex field=_raw "\\"src\\":[^}}]+\\"country\\":\\s*\\"(?<src_country>[^\\"]+)\\"" | rex field=_raw "\\"cat\\":\\s*\\"(?<threat_category>[^\\"]+)\\"" | stats count by src_country, threat_category | sort -count'
        }
        
        for name, query in queries.items():
            print(f"### {name}")
            print(f"```spl")
            print(query)
            print("```\n")
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write("# Splunk Security Analysis Queries\n\n")
                f.write(f"Time Window: {time_window}\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                for name, query in queries.items():
                    f.write(f"## {name}\n")
                    f.write(f"```spl\n{query}\n```\n\n")
            print(f"Queries saved to: {args.output}")
        
        return
    
    # Create analyzer
    analyzer = SplunkSecurityAnalyzer(
        args.splunk_host,
        args.splunk_user,
        args.splunk_pass,
        args.anthropic_key
    )
    
    # Run analysis
    output_file = args.output
    if args.update_existing:
        output_file = 'syslog_security_analysis_updated.md'
    
    analyzer.run(output_file, args.time_window)


if __name__ == "__main__":
    main()