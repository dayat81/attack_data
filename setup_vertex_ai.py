#!/usr/bin/env python3
"""
Setup and configure Vertex AI model and endpoint for attack detection.
"""
import json
import logging
import google.cloud.aiplatform as aiplatform
import argparse
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class VertexAISetup:
    def __init__(self, config_path):
        """Initialize Vertex AI setup with configuration."""
        with open(config_path) as f:
            self.config = json.load(f)
        
        # Initialize Vertex AI
        aiplatform.init(
            project=self.config['project_id'],
            location=self.config['region']
        )
        
        self.model = None
        self.endpoint = None

    def upload_model(self):
        """Upload a model to Vertex AI from GCS."""
        logger.info(f"Checking for existing model: {self.config['model_id']}")
        models = aiplatform.Model.list(filter=f"display_name={self.config['model_id']}")
        
        if models:
            self.model = models[0]
            logger.info(f"Using existing model: {self.model.resource_name}")
            return self.model

        logger.info("Uploading new model from GCS...")
        self.model = aiplatform.Model.upload(
            display_name=self.config['model_id'],
            artifact_uri="gs://attack-data-model-bucket/",
            serving_container_predict_route="/predict",
            serving_container_health_route="/health",
            serving_container_image_uri="us-docker.pkg.dev/vertex-ai/prediction/sklearn-cpu.1-0:latest",
        )
        logger.info(f"Uploaded new model: {self.model.resource_name}")
        return self.model

    def deploy_model(self):
        """Deploy the model to an endpoint."""
        logger.info(f"Checking for existing endpoint: {self.config['endpoint_id']}")
        endpoints = aiplatform.Endpoint.list(filter=f"display_name={self.config['endpoint_id']}")
        
        if endpoints:
            self.endpoint = endpoints[0]
            logger.info(f"Using existing endpoint: {self.endpoint.resource_name}")
        else:
            logger.info("Creating new endpoint...")
            self.endpoint = aiplatform.Endpoint.create(
                display_name=self.config['endpoint_id'],
            )
            logger.info(f"Created new endpoint: {self.endpoint.resource_name}")

        logger.info("Deploying model to endpoint...")
        self.endpoint.deploy(
            model=self.model,
            deployed_model_display_name=self.config['model_id'],
            machine_type=self.config['machine_type'],
            min_replica_count=1,
            max_replica_count=1,
        )
        logger.info("Model deployed to endpoint.")

    def test_endpoint(self):
        """Test the deployed endpoint with the test dataset."""
        import requests
        import json
        logger.info("Testing Cloud Function with test dataset...")
        url = "https://us-central1-northern-center-462508-k6.cloudfunctions.net/attack-detection-function"
        
        with open('all_parsed_data.json', 'r') as f:
            dataset = json.load(f)

        # Find the first record labeled as an attack to test
        attack_record = None
        for record in dataset:
            if record.get('target') == 1:
                attack_record = record
                break
        
        if not attack_record:
            logger.error("No attack record found in the dataset to test.")
            return

        logger.info(f"Found attack record to test: {attack_record}")
        features = [[attack_record.get('feat1', 0), 
                     attack_record.get('feat2', 0), 
                     attack_record.get('feat3', 0), 
                     attack_record.get('feat4', 0)]]
        
        data = {"instances": features}
        logger.info(f"Sending test record to endpoint: {features}")
        response = requests.post(url, json=data)
        logger.info(f"Prediction result: {response.text}")

def main():
    parser = argparse.ArgumentParser(description='Setup Vertex AI model and endpoint')
    parser.add_argument('--config', type=str, default='vertex_config.json',
                        help='Path to Vertex AI configuration file')
    parser.add_argument('--test', action='store_true',
                        help='Test the endpoint after setup')
    
    args = parser.parse_args()
    
    try:
        # Initialize setup
        setup = VertexAISetup(args.config)
        

        
        # Test if requested
        if args.test:
            setup.test_endpoint()
    
    except Exception as e:
        logger.error(f"Error during Vertex AI setup: {str(e)}")
        raise

if __name__ == "__main__":
    main()
