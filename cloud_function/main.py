import joblib
from google.cloud import storage
import json

# Initialize GCS client
storage_client = storage.Client()

# Download the model from GCS
bucket = storage_client.bucket('attack-data-model-bucket')
blob = bucket.blob('model.joblib')
blob.download_to_filename('/tmp/model.joblib')

# Load the model
model = joblib.load('/tmp/model.joblib')

def predict(request):
    """HTTP-triggered Cloud Function to make predictions."""
    request_json = request.get_json()
    if request_json and 'instances' in request_json:
        instances = request_json['instances']
        prediction = model.predict(instances).tolist()
        return json.dumps({'predictions': prediction})
    else:
        return 'Error: Invalid request format.', 400
