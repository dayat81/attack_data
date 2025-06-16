# Network Attack Data Pipeline Configuration Guide

## Prerequisites

### Google Cloud Setup
1. Active Google Cloud project
2. Enabled APIs:
   - Datastore API
   - Vertex AI API
   - Cloud Logging API
3. Service account with required permissions:
   - Datastore Admin
   - Vertex AI Admin
   - Cloud Logging Admin

### Environment Variables
```bash
export GOOGLE_APPLICATION_CREDENTIALS="path/to/service-account.json"
export PROJECT_ID="your-project-id"
```

## Configuration Files

### Vertex AI Configuration
Create a JSON file (e.g., `vertex_config.json`):
```json
{
    "project_id": "your-project-id",
    "region": "us-central1",
    "model_id": "your-model-id"
}
```

## Directory Structure
```
attack_data/
├── docs/
│   ├── configuration.md
│   └── datastore_instance_details.txt
├── test_data/
│   └── test_input.json
├── data_pipeline.py
├── datastore_instance_checker.py
├── logging_utils.py
├── vertex_ai_utils.py
├── test_pipeline.py
└── requirements.txt
```

## Logging Structure

### Local Logging
- Log files are created in the current directory
- Format: `%(asctime)s - %(name)s - %(levelname)s - %(message)s`
- Levels: DEBUG, INFO, WARNING, ERROR, CRITICAL

### Cloud Logging
- Logs are automatically sent to Google Cloud Logging
- Structured logs with additional metadata
- Accessible through Google Cloud Console

## Usage Examples

### Verify Datastore Instance
```bash
python datastore_instance_checker.py \
    --project_id your-project-id \
    --instance_id your-instance-id
```

### Process Data
```bash
python data_pipeline.py \
    --project_id your-project-id \
    --datastore_kind AttackData \
    --datastore_namespace attack_data \
    --vertex_config vertex_config.json \
    --input_file path/to/your/data.json
```

### Run Tests
```bash
python test_pipeline.py
```

## Error Handling

### Common Error Scenarios
1. Authentication failures
2. Datastore connection issues
3. Vertex AI processing errors
4. Data transformation failures

### Log Locations
- Local logs: current directory
- Cloud logs: Google Cloud Console > Logging

## Monitoring

### Metrics to Monitor
1. Data ingestion rate
2. Vertex AI prediction latency
3. Error rates
4. Data transformation failures

### Alerting
- High error rates
- Failed data ingestion
- Vertex AI service issues
- Resource utilization
