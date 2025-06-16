# Network Attack Data Pipeline Troubleshooting Guide

## Common Issues and Solutions

### 1. Authentication Errors
**Symptoms:"
- `PermissionDenied` errors when accessing Google Cloud services
- `Authentication credentials not found` error

**Solution:"
1. Verify service account credentials:
```bash
export GOOGLE_APPLICATION_CREDENTIALS="path/to/your/service-account.json"
```
2. Check if service account has required permissions:
- Datastore Admin
- Vertex AI Admin
- Cloud Logging Admin
- Pub/Sub Admin

### 2. Data Ingestion Issues
**Symptoms:"
- Data not appearing in Datastore
- High error rates in logs
- Slow ingestion performance

**Solution:"
1. Verify Datastore instance status:
```bash
python datastore_instance_checker.py --project_id your-project-id
```
2. Check logs for specific errors:
```bash
gcloud logging read "resource.type=cloud_function"
```
3. Verify data schema compatibility

### 3. Vertex AI Prediction Issues
**Symptoms:"
- High prediction latency
- Prediction errors
- Model not found

**Solution:"
1. Verify model deployment:
```bash
gcloud ai models list --region=us-central1
```
2. Check endpoint status:
```bash
gcloud ai endpoints describe attack-detection-endpoint --region=us-central1
```
3. Verify model version:
```bash
gcloud ai models versions list --model=attack-detection-model --region=us-central1
```

### 4. Monitoring Issues
**Symptoms:"
- Missing metrics in dashboard
- Alert notifications not working
- Dashboard not updating

**Solution:"
1. Verify monitoring permissions:
```bash
gcloud projects get-iam-policy your-project-id
```
2. Check notification channel configuration:
```bash
gcloud alpha monitoring channels list
```
3. Verify alert policy:
```bash
gcloud alpha monitoring policies list
```

### 5. Storage Issues
**Symptoms:"
- Storage quota exceeded
- Slow data access
- Data not being cleaned up

**Solution:"
1. Check storage usage:
```bash
gsutil du -h gs://your-bucket-name
```
2. Verify lifecycle rules:
```bash
gsutil lifecycle get gs://your-bucket-name
```
3. Clean up old data:
```bash
gcloud scheduler jobs run cleanup-job
```

## Log Analysis

### Common Log Messages
```python
# Data ingestion errors
"Error ingesting data to Datastore: {error details}"

# Vertex AI errors
"Error processing with Vertex AI: {error details}"

# Authentication errors
"Permission denied: {resource}"
```

### Log Levels
- `INFO`: Normal operations
- `WARNING`: Potential issues
- `ERROR`: Critical failures
- `CRITICAL`: System failure

## Performance Optimization

### 1. Data Ingestion
- Use batch processing for large datasets
- Implement retry logic for failed operations
- Monitor and adjust batch sizes

### 2. Vertex AI
- Optimize model serving configuration
- Use appropriate machine types
- Implement caching for repeated predictions

### 3. Storage
- Use appropriate storage classes
- Implement lifecycle management
- Monitor and adjust cleanup schedules

## Security Best Practices

### 1. Access Control
- Use least privilege principle
- Regularly review IAM permissions
- Enable audit logging

### 2. Data Protection
- Enable encryption at rest
- Implement data retention policies
- Regularly backup important data

### 3. Monitoring
- Enable audit logs
- Set up alerting for suspicious activity
- Regularly review access patterns

## Recovery Procedures

### 1. Data Recovery
1. Check backup history
2. Restore from latest backup
3. Verify data integrity

### 2. Service Recovery
1. Check service status
2. Restart affected services
3. Verify functionality

### 3. Configuration Recovery
1. Check version history
2. Restore previous configuration
3. Verify settings

## Additional Resources

- [Google Cloud Monitoring Documentation](https://cloud.google.com/monitoring)
- [Vertex AI Documentation](https://cloud.google.com/vertex-ai)
- [Datastore Documentation](https://cloud.google.com/datastore)
- [Cloud Logging Documentation](https://cloud.google.com/logging)

## Support

For additional support, please:
1. Check the [documentation](./documentation.md)
2. Search existing issues
3. Open a new issue with detailed information
