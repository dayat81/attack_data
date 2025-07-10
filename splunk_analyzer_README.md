# Splunk Security Analyzer with Anthropic LLM

This script fetches security events from Splunk and uses Anthropic's Claude AI to analyze patterns and generate security insights.

## Features

- Automated Splunk data retrieval via REST API
- Intelligent analysis using Claude AI
- Comparison with previous security reports
- Identifies new threats and changed patterns
- Generates actionable recommendations

## Setup

### 1. Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/Mac:
source venv/bin/activate

# On Windows:
# venv\Scripts\activate

# Verify activation (should show venv path)
which python
```

### 2. Install Requirements

```bash
# With venv activated, install dependencies
pip install requests anthropic

# Or create a requirements.txt file
echo "requests>=2.31.0
anthropic>=0.18.0" > requirements.txt

pip install -r requirements.txt
```

### 3. Verify Installation

```bash
# Check installed packages
pip list | grep -E "requests|anthropic"
```

## Usage

### Basic Usage
```bash
python splunk_security_analyzer.py --anthropic-key YOUR_API_KEY
```

### Specify Time Window
```bash
# Last 24 hours (default)
python splunk_security_analyzer.py --anthropic-key YOUR_API_KEY

# Last 7 days
python splunk_security_analyzer.py --anthropic-key YOUR_API_KEY --time-window -7d

# Last 30 days
python splunk_security_analyzer.py --anthropic-key YOUR_API_KEY --time-window -30d

# Last 1 hour
python splunk_security_analyzer.py --anthropic-key YOUR_API_KEY --time-window -1h

# Custom time ranges (Splunk format)
python splunk_security_analyzer.py --anthropic-key YOUR_API_KEY --time-window -2w  # 2 weeks
```

### Custom Splunk Instance
```bash
python splunk_security_analyzer.py \
    --splunk-host http://your-splunk:8000 \
    --splunk-user admin \
    --splunk-pass yourpassword \
    --anthropic-key YOUR_API_KEY
```

### Save Report to File
```bash
python splunk_security_analyzer.py \
    --anthropic-key YOUR_API_KEY \
    --output security_report_$(date +%Y%m%d).md
```

### Update Existing Report
```bash
python splunk_security_analyzer.py \
    --anthropic-key YOUR_API_KEY \
    --update-existing
```

### Generate Queries Only (No Analysis)
```bash
# Generate queries to verify in Splunk GUI
python splunk_security_analyzer.py --generate-queries-only

# Generate queries for specific time window
python splunk_security_analyzer.py --generate-queries-only --time-window -7d

# Save queries to file
python splunk_security_analyzer.py --generate-queries-only -o splunk_queries.md
```

## What It Analyzes

The script automatically queries Splunk for:
- Critical security alerts (severity >= 4)
- New attacking IP addresses
- Exploitation attempts and CVEs
- Suspicious domains (DGA, C2, Cobalt Strike)
- MITRE ATT&CK patterns
- Recent security events (last hour)

## Output

The script generates a comprehensive report including:
- Executive summary of new findings
- Comparison with previous reports
- Critical security issues
- Trend analysis
- Specific recommendations
- **Splunk queries used for verification**
- Timestamp and metadata

### Query Verification Feature
The report now includes all Splunk queries used during analysis, formatted for easy copy-paste into Splunk Web GUI. This allows you to:
- Verify the analysis results
- Run queries manually for deeper investigation
- Customize queries for your specific needs

## Example Commands

```bash
# Analyze last 24 hours (default)
python splunk_security_analyzer.py \
    --splunk-host http://10.213.10.3:8000 \
    --splunk-user admin \
    --splunk-pass admin123 \
    --anthropic-key sk-ant-api... \
    --output updated_security_analysis.md

# Analyze last week's data
python splunk_security_analyzer.py \
    --anthropic-key YOUR_API_KEY \
    --time-window -7d \
    --output weekly_security_report.md

# Quick 1-hour analysis for recent incidents
python splunk_security_analyzer.py \
    --anthropic-key YOUR_API_KEY \
    --time-window -1h
```

## Security Notes

- The script disables SSL verification for self-signed certificates
- Credentials should be stored securely (consider environment variables)
- API keys should never be committed to version control

## Environment Variables (Optional)

```bash
export ANTHROPIC_API_KEY="your-key-here"
export SPLUNK_HOST="http://10.213.10.3:8000"
export SPLUNK_USER="admin"
export SPLUNK_PASS="admin123"
```

## Quick Start with Virtual Environment

```bash
# Complete setup and run
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
pip install requests anthropic
python splunk_security_analyzer.py --anthropic-key YOUR_API_KEY --output security_insights.md

# Deactivate when done
deactivate
```