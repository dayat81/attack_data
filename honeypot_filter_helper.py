#!/usr/bin/env python3
"""
Honeypot Filter Helper - Generate Splunk queries with honeypot IP filtering
"""

# Honeypot IP suffixes to filter
HONEYPOT_SUFFIXES = [102, 88, 96, 86, 91, 98, 101, 10, 108, 6, 77, 78, 79, 80, 83, 84, 87, 89, 93, 97, 94, 95]

def generate_honeypot_filter():
    """Generate the regex pattern for honeypot filtering"""
    suffix_pattern = "|".join(str(s) for s in HONEYPOT_SUFFIXES)
    return f'\\.\\*({suffix_pattern})$'

def add_honeypot_filter_to_query(base_query):
    """Add honeypot filtering to a Splunk query"""
    filter_pattern = generate_honeypot_filter()
    
    # Check if query already has rex field extraction
    if "rex field=_raw" not in base_query:
        # Add field extraction first
        filter_addition = f'''
| rex field=_raw "\\"src\\":\\s*{{\\s*\\"ip\\":\\s*\\"(?<src_ip>[^\\"]+)\\""" 
| rex field=_raw "\\"dst\\":\\s*{{\\s*\\"ip\\":\\s*\\"(?<dst_ip>[^\\"]+)\\""" 
| regex src_ip!="{filter_pattern}" 
| regex dst_ip!="{filter_pattern}"'''
    else:
        # Just add the regex filters
        filter_addition = f'''
| regex src_ip!="{filter_pattern}" 
| regex dst_ip!="{filter_pattern}"'''
    
    return base_query + filter_addition

def print_examples():
    """Print example queries with honeypot filtering"""
    print("HONEYPOT FILTER EXAMPLES")
    print("=" * 80)
    print(f"\nHoneypot IP suffixes to filter: {HONEYPOT_SUFFIXES}")
    print(f"\nFilter pattern: {generate_honeypot_filter()}")
    print("\n" + "=" * 80)
    
    # Example 1: Simple attack search
    print("\n1. SIMPLE ATTACK SEARCH (with honeypot filter):")
    print("-" * 40)
    query1 = 'index=main sourcetype=syslog "ATTACK"'
    print("Original:")
    print(f"```\n{query1}\n```")
    print("\nWith honeypot filter:")
    print(f"```{add_honeypot_filter_to_query(query1)}\n```")
    
    # Example 2: CVE search
    print("\n2. CVE EXPLOITATION SEARCH (with honeypot filter):")
    print("-" * 40)
    query2 = '''index=main sourcetype=syslog CVE-* 
| rex field=_raw "\\"s_msg\\":\\s*\\"(?<alert>[^\\"]+)\\""" 
| table _time, src_ip, dst_ip, alert'''
    print("Original:")
    print(f"```\n{query2}\n```")
    print("\nWith honeypot filter:")
    print(f"```{add_honeypot_filter_to_query(query2)}\n```")
    
    # Example 3: Stats query
    print("\n3. THREAT ACTOR STATS (with honeypot filter):")
    print("-" * 40)
    query3 = '''index=main sourcetype=syslog s_pr>=3 
| rex field=_raw "\\"src\\":\\s*{{\\s*\\"ip\\":\\s*\\"(?<attacker>[^\\"]+)\\""" 
| stats count by attacker 
| sort -count'''
    print("With honeypot filter:")
    filtered_query3 = query3.replace('| stats', f'| regex attacker!="{generate_honeypot_filter()}" \n| stats')
    print(f"```\n{filtered_query3}\n```")
    
    # Verification query
    print("\n4. VERIFY HONEYPOT FILTERING:")
    print("-" * 40)
    verify_query = f'''index=main sourcetype=syslog 
| rex field=_raw "\\"dst\\":\\s*{{\\s*\\"ip\\":\\s*\\"(?<ip>[^\\"]+)\\""" 
| eval is_honeypot=if(match(ip, "{generate_honeypot_filter()}"), "YES", "NO")
| stats count by is_honeypot'''
    print(f"```\n{verify_query}\n```")
    
    print("\n" + "=" * 80)
    print("\nUSAGE TIPS:")
    print("1. Add the honeypot filter after field extraction (rex) but before stats/table")
    print("2. Use 'src_ip' for source filtering, 'dst_ip' for destination filtering")
    print("3. For custom field names, adjust the regex accordingly")
    print("4. Consider saving as a Splunk macro for reusability")

if __name__ == "__main__":
    print_examples()