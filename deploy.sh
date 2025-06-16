#!/bin/bash

# Enable required APIs
gcloud services enable \
    datastore.googleapis.com \
    aiplatform.googleapis.com \
    logging.googleapis.com \
    pubsub.googleapis.com

echo "Enabled required Google Cloud APIs"

# Create Cloud Storage bucket for data
BUCKET_NAME="attack-data-$PROJECT_ID"
gsutil mb gs://$BUCKET_NAME

echo "Created Cloud Storage bucket: $BUCKET_NAME"

# Create Pub/Sub topic for real-time processing
gcloud pubsub topics create attack-data-stream

echo "Created Pub/Sub topic: attack-data-stream"

# Set up logging
LOG_BUCKET="attack-data-logs-$PROJECT_ID"
gsutil mb gs://$LOG_BUCKET

echo "Created logging bucket: $LOG_BUCKET"

# Grant necessary permissions
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$PROJECT_ID@appspot.gserviceaccount.com" \
    --role="roles/datastore.user"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$PROJECT_ID@appspot.gserviceaccount.com" \
    --role="roles/aiplatform.user"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$PROJECT_ID@appspot.gserviceaccount.com" \
    --role="roles/logging.logWriter"

echo "Set up IAM permissions"

# Deploy Cloud Function for real-time processing
gcloud functions deploy process-attack-data \
    --runtime python311 \
    --trigger-topic attack-data-stream \
    --source ./functions \
    --entry-point process_attack_data

echo "Deployed Cloud Function for real-time processing"

# Create Datastore indexes
gcloud datastore indexes create ./indexes.yaml

echo "Created Datastore indexes"

# Create Vertex AI endpoint
gcloud ai endpoints create \
    --region=us-central1 \
    --display-name=attack-detection-endpoint

echo "Created Vertex AI endpoint"

# Create Cloud Monitoring dashboard
gcloud monitoring dashboards create \
    --config-from-file=./dashboard.json

echo "Created Cloud Monitoring dashboard"

# Create Cloud Logging sink
gcloud logging sinks create attack-data-sink \
    storage.googleapis.com/$LOG_BUCKET \
    --log-filter='resource.type="cloud_datastore" OR resource.type="cloud_function"'

echo "Created Cloud Logging sink"

# Create Cloud Scheduler job for periodic data cleanup
gcloud scheduler jobs create pubsub cleanup-job \
    --schedule="0 0 * * *" \
    --topic=cleanup-topic \
    --message-body="cleanup_old_data"

echo "Created Cloud Scheduler job for data cleanup"

# Create Cloud Storage lifecycle rules
LIFECYCLE_CONFIG='{
    "rule": [
        {
            "action": {"type": "Delete"},
            "condition": {"age": 30}
        }
    ]
}'

gsutil lifecycle set -f <(echo "$LIFECYCLE_CONFIG") gs://$BUCKET_NAME

echo "Set up Cloud Storage lifecycle rules"

# Create Cloud Monitoring alerting policies
gcloud alpha monitoring policies create-from-file \
    ./alerting/attack-detection-policy.yaml

echo "Created Cloud Monitoring alerting policies"
