import logging
from google.cloud import aiplatform
from google.cloud import pubsub_v1
from google.api_core.exceptions import NotFound, GoogleAPIError
import json
from typing import Dict, Any, Optional, List
import os
from datetime import datetime

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('vertex_ai_processor')

class VertexAIProcessor:
    def __init__(self, project_id: str, region: str, model_id: str, endpoint_id: Optional[str] = None):
        """
        Initialize Vertex AI processor with required credentials.
        
        Args:
            project_id: Google Cloud project ID
            region: GCP region (e.g., 'us-central1')
            model_id: Vertex AI model ID
            endpoint_id: Optional endpoint ID (defaults to f"{model_id}-endpoint")
        """
        self.project_id = project_id
        self.region = region
        self.model_id = model_id
        self.endpoint_id = endpoint_id or f"{model_id}-endpoint"
        
        # Initialize clients
        self.publisher = pubsub_v1.PublisherClient()
        aiplatform.init(project=project_id, location=region)
        
        # Lazy-loaded resources
        self._endpoint = None
        self._model = None
        
        logger.info(
            "Initialized VertexAIProcessor",
            extra={
                "project_id": project_id,
                "region": region,
                "model_id": model_id,
                "endpoint_id": self.endpoint_id
            }
        )

    @property
    def endpoint(self):
        """Lazy-load and return the Vertex AI endpoint."""
        if self._endpoint is None:
            try:
                self._endpoint = aiplatform.Endpoint(
                    endpoint_name=f"projects/{self.project_id}/locations/{self.region}/endpoints/{self.endpoint_id}"
                )
                logger.info(f"Connected to Vertex AI endpoint: {self.endpoint_id}")
            except Exception as e:
                logger.error(
                    f"Failed to connect to Vertex AI endpoint {self.endpoint_id}",
                    exc_info=True
                )
                raise
        return self._endpoint
    
    def preprocess_data(self, data: Dict[str, Any]) -> List[List[float]]:
        """
        Preprocess data for the scikit-learn model.
        
        Args:
            data: Raw data dictionary with network event details
            
        Returns:
            A list containing a list of features for prediction.
            
        Raises:
            ValueError: If required fields are missing
        """
        try:
            # Extract and validate required fields
            required_fields = ['feat1', 'feat2', 'feat3', 'feat4']
            missing_fields = [field for field in required_fields if field not in data]
            
            if missing_fields:
                raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")
            
            # Create feature list with proper typing
            features = [
                float(data['feat1']),
                float(data['feat2'])
            ]
            
            logger.debug(
                "Preprocessed data for prediction",
                extra={"features": features}
            )
            
            return [features]
            
        except (ValueError, TypeError) as e:
            logger.error(
                "Data preprocessing failed",
                extra={
                    "error": str(e),
                    "data_type": type(data).__name__,
                    "data_keys": list(data.keys()) if isinstance(data, dict) else []
                },
                exc_info=True
            )
            raise

    def send_to_vertex_ai(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send data to the Cloud Function for prediction.
        
        Args:
            data: Dictionary containing network event data
            
        Returns:
            Dictionary containing prediction results and metadata
            
        Raises:
            GoogleAPIError: If there's an error communicating with the Cloud Function
            ValueError: If the prediction response is malformed
        """
        import requests
        try:
            # Preprocess the input data
            features = self.preprocess_data(data)
            
            # Make prediction
            logger.debug("Sending prediction request to Cloud Function", extra={"features": features})
            url = "https://us-central1-northern-center-462508-k6.cloudfunctions.net/attack-detection-function"
            request_data = {"instances": features}
            response = requests.post(url, json=request_data)
            response.raise_for_status()  # Raise an exception for bad status codes
            
            prediction = response.json()
            
            # Format result with metadata
            result = {
                'prediction': prediction['predictions'][0],
                'model': 'cloud-function-model',
                'endpoint': url,
                'timestamp': datetime.utcnow().isoformat(),
                'features': features
            }
            
            logger.info(
                "Received prediction from Cloud Function",
                extra={
                    "model": 'cloud-function-model',
                    "endpoint": url,
                    "prediction": prediction
                }
            )
            
            return result
            
        except Exception as e:
            logger.error(
                "Prediction request failed",
                extra={
                    "error": str(e),
                    "model": self.model_id,
                    "endpoint": self.endpoint_id
                },
                exc_info=True
            )
            raise GoogleAPIError(f"Vertex AI prediction failed: {str(e)}") from e

    def publish_to_pubsub(self, topic_id: str, data: Dict[str, Any]) -> str:
        """
        Publish prediction results to a Pub/Sub topic.
        
        Args:
            topic_id: ID of the Pub/Sub topic
            data: Data to publish (will be JSON-serialized)
            
        Returns:
            Message ID from Pub/Sub
            
        Raises:
            GoogleAPIError: If publishing fails
        """
        try:
            topic_path = self.publisher.topic_path(self.project_id, topic_id)
            
            # Ensure data is JSON-serializable
            serializable_data = json.loads(json.dumps(data, default=str))
            message_bytes = json.dumps(serializable_data).encode("utf-8")
            
            # Publish message
            future = self.publisher.publish(topic_path, data=message_bytes)
            message_id = future.result()
            
            logger.info(
                "Published message to Pub/Sub",
                extra={
                    "topic_id": topic_id,
                    "message_id": message_id,
                    "data_keys": list(data.keys()) if isinstance(data, dict) else []
                }
            )
            
            return message_id
            
        except Exception as e:
            logger.error(
                "Failed to publish to Pub/Sub",
                extra={
                    "topic_id": topic_id,
                    "error": str(e)
                },
                exc_info=True
            )
            raise GoogleAPIError(f"Pub/Sub publish failed: {str(e)}") from e
            
    def process_and_predict(self, data: Dict[str, Any], pubsub_topic: Optional[str] = None) -> Dict[str, Any]:
        """
        Process data, get prediction, and optionally publish to Pub/Sub.
        
        Args:
            data: Input data for prediction
            pubsub_topic: Optional Pub/Sub topic to publish results to
            
        Returns:
            Dictionary with prediction results and metadata
        """
        try:
            # Get prediction
            result = self.send_to_vertex_ai(data)
            
            # Publish to Pub/Sub if topic is provided
            if pubsub_topic:
                try:
                    message_id = self.publish_to_pubsub(pubsub_topic, result)
                    result['pubsub_message_id'] = message_id
                except Exception as pubsub_error:
                    logger.warning(
                        "Pub/Sub publish failed (continuing)",
                        extra={"error": str(pubsub_error)}
                    )
            
            return result
            
        except Exception as e:
            logger.error(
                "Prediction pipeline failed",
                extra={"error": str(e)},
                exc_info=True
            )
            raise
