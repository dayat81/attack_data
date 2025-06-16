import re
import json
import argparse
import os

# --- Feature Definitions ---
# feat1: is_suspicious_process (binary: 1 if known suspicious process name is found)
# feat2: elevation_type (integer: from Token Elevation Type)
# feat3: sysmon_event_id (integer: from Sysmon Event IDs)
# feat4: powershell_script_block_length (integer: length of PowerShell script blocks)

def get_target_label(log_path):
    """Determine the target label based on the log file's path."""
    path_lower = log_path.lower()
    if 'attack_techniques' in path_lower or 'malware' in path_lower:
        return 1
    # Assume honeypot data is benign for now
    if 'honeypots' in path_lower:
        return 0
    # Suspicious behavior is a potential attack
    if 'suspicious_behaviour' in path_lower:
        return 1
    return 0

def parse_fgdump(content):
    """Parser for fgdump logs."""
    features = {}
    if re.search(r'fgdump.exe', content, re.IGNORECASE):
        features['feat1'] = 1
    token_match = re.search(r'Token Elevation Type:\s+%%(\d+)', content)
    if token_match:
        features['feat2'] = int(token_match.group(1))
    return features

def parse_sysmon(content):
    """Basic parser for sysmon logs."""
    features = {}
    event_id_match = re.search(r'<EventID>(\d+)</EventID>', content)
    if event_id_match:
        features['feat3'] = int(event_id_match.group(1))
    # Look for suspicious processes in sysmon logs as well
    if re.search(r'mimikatz.exe|powershell.exe', content, re.IGNORECASE):
        features['feat1'] = 1
    return features

def parse_powershell(content):
    """Basic parser for powershell logs."""
    features = {}
    # Find all script blocks and get the length of the longest one
    script_blocks = re.findall(r'ScriptBlockText=(.*)', content)
    if script_blocks:
        features['feat4'] = max(len(block) for block in script_blocks)
    return features


def parse_log_file(log_path):
    """Dispatcher function to parse a single log file."""
    # Default feature values
    features = {'feat1': 0, 'feat2': 0, 'feat3': 0, 'feat4': 0}
    
    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        print(f"Could not read {log_path}: {e}")
        return None

    # Dispatch to the correct parser based on filename/path
    filename = os.path.basename(log_path).lower()
    if 'fgdump' in filename:
        features.update(parse_fgdump(content))
    elif 'sysmon' in filename:
        features.update(parse_sysmon(content))
    elif 'powershell' in filename:
        features.update(parse_powershell(content))
    
    # Add the target label
    features['target'] = get_target_label(log_path)
    
    return features

def main():
    parser = argparse.ArgumentParser(description='Parse all log files in a directory to extract features.')
    parser.add_argument('--input_dir', default='datasets', help='Root directory of the logs to parse.')
    parser.add_argument('--output_file', default='all_parsed_data.json', help='Path to the output JSON file.')
    args = parser.parse_args()

    all_features = []
    for root, _, files in os.walk(args.input_dir):
        for file in files:
            if file.endswith('.log'):
                log_path = os.path.join(root, file)
                print(f"Processing {log_path}...")
                parsed_features = parse_log_file(log_path)
                if parsed_features:
                    all_features.append(parsed_features)

    with open(args.output_file, 'w') as f:
        json.dump(all_features, f, indent=4)
        
    print(f"\nSuccessfully parsed {len(all_features)} log files.")
    print(f"Saved combined feature data to {args.output_file}")

if __name__ == '__main__':
    main()
