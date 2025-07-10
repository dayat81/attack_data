# CLAUDE.md
sudo password is admin123
splunk web http://10.213.10.3:8000/en-GB/app/search admin admin123
This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview
This is a network attack data repository that collects and organizes security datasets by MITRE ATT&CK techniques. It includes a Google Cloud-based pipeline for threat detection using Vertex AI and an AWS Batch service for automated attack data generation.

## Common Development Commands

### Testing
```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_log_parser.py

# Run with verbose output
pytest -v
```

### Data Pipeline Operations
```bash
# Check Datastore instance status
python datastore_instance_checker.py --project_id <project-id> --instance_id <instance-id>

# Process attack data through the pipeline
python data_pipeline.py \
    --project_id <project-id> \
    --datastore_kind AttackData \
    --datastore_namespace attack_data \
    --vertex_config vertex_config.json \
    --input_file <path/to/data.json>

# Test pipeline functionality
python test_pipeline.py
```

### Data Replay for Testing
```bash
# Replay attack data into Splunk
cd bin
python replay.py -c replay.yml
```

### Deployment
```bash
# Enable Google Cloud APIs and deploy infrastructure
./deploy.sh enable-apis
```

## Architecture Overview

### Core Components
1. **Data Pipeline** (`data_pipeline.py`, `data_ingestion.py`)
   - Ingests attack data to Google Cloud Datastore
   - Integrates with Vertex AI for threat detection
   - Handles structured logging via `logging_utils.py`

2. **Attack Data Service** (`/attack_data_service/`)
   - AWS Batch-based automated data generation
   - Uses Attack Range for simulations
   - Generates PR with new datasets

3. **Dataset Organization** (`/datasets/`)
   - Organized by MITRE ATT&CK technique IDs (e.g., T1003.001)
   - Each dataset includes YAML metadata with:
     - Technique references
     - Environment descriptions
     - Sourcetypes
     - Dataset URLs

4. **Cloud Integration**
   - **Vertex AI**: Real-time threat detection (`vertex_ai_utils.py`)
   - **Datastore**: Attack data storage (`datastore_utils.py`)
   - **Cloud Functions**: Real-time processing (`/cloud_function/`)
   - **Monitoring**: Cloud Monitoring dashboards and alerts

### Key Design Patterns
- Log parsers extract features from different log types (Sysmon, PowerShell, FGDump)
- Target labels determined by file path patterns (attack_techniques/malware = 1, honeypots = 0)
- Structured logging throughout for monitoring
- Environment configurations stored as markdown in `/environments/`

## Important Files
- `vertex_config.json`: Vertex AI model configuration (Git LFS)
- `requirements.txt`: Python dependencies for Google Cloud services
- `pytest.ini`: Test configuration
- `.github/workflows/`: CI/CD automation including data validation