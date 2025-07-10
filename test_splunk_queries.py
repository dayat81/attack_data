#!/usr/bin/env python3
"""
Test script to generate and display Splunk queries with proper syntax
"""

import sys

def generate_test_queries(time_window="-24h"):
    """Generate properly formatted Splunk queries"""
    
    print(f"\n=== SPLUNK QUERY SYNTAX TEST ===")
    print(f"Time Window: {time_window}\n")
    
    # Test query with proper syntax
    test_query = f"""
### Critical Alerts (Correct Syntax)
```spl
index=main sourcetype=syslog (severity>=4 OR "CRITICAL" OR "HIGH") earliest={time_window} latest=now | head 100
```

### Common Syntax Errors to Avoid:
1. ❌ WRONG: `| head 100 earliest=-7d`
2. ✅ CORRECT: `earliest=-7d latest=now | head 100`

### Time Modifiers Must Be At Search Level:
```spl
index=main sourcetype=syslog earliest={time_window} latest=now | search "ATTACK" | stats count
```

### Complex Query Example:
```spl
index=main sourcetype=syslog earliest={time_window} latest=now 
| rex field=_raw "\\"src\\":\\s*{{\\s*\\"ip\\":\\s*\\"(?<src_ip>[^\\"]+)\\"" 
| rex field=_raw "\\"dst\\":\\s*{{\\s*\\"ip\\":\\s*\\"(?<dst_ip>[^\\"]+)\\"" 
| stats count by src_ip, dst_ip 
| where count > 1
```
"""
    
    print(test_query)

if __name__ == "__main__":
    time_window = sys.argv[1] if len(sys.argv) > 1 else "-24h"
    generate_test_queries(time_window)