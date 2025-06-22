import json
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional, Any, Union, Tuple

from google.cloud import datastore
from google.cloud.datastore import Client, Entity
from google.api_core.exceptions import GoogleAPIError

from logging_utils import PipelineLogger
from vertex_ai_utils import VertexAIProcessor, GoogleAPIError as VertexAIError

class DataPipeline:
    def __init__(self, project_id: str, datastore_kind: str, datastore_namespace: Optional[str] = None, 
                 vertex_config: Optional[Dict[str, Any]] = None):
        """
        Initialize the data pipeline with Google Cloud services integration.
        
        Args:
            project_id: Google Cloud project ID
            datastore_kind: Datastore entity kind for storing records
            datastore_namespace: Optional namespace for Datastore entities
            vertex_config: Configuration for Vertex AI integration (dict with 'project_id', 'region', 'model_id', etc.)
        """
        self.project_id = project_id
        self.datastore_kind = datastore_kind
        self.datastore_namespace = datastore_namespace
        self.vertex_config = vertex_config or {}
        
        # Initialize logger with structured logging
        # PipelineLogger currently only accepts ``project_id`` and ``log_name``
        # parameters.  The previous implementation attempted to pass arguments
        # such as ``name`` and ``level`` which are not supported and resulted in
        # ``TypeError`` during initialization.  Provide supported parameters and
        # log the contextual fields manually.
        self.logger = PipelineLogger(
            project_id=project_id,
            log_name='attack_data_pipeline'
        )

        # Store default fields used in every log entry
        self._log_context = {
            'project_id': project_id,
            'datastore_kind': datastore_kind,
            'datastore_namespace': datastore_namespace,
        }
        
        # Initialize Datastore client with error handling
        try:
            self.datastore_client = datastore.Client(
                project=project_id,
                namespace=datastore_namespace
            )
            self.logger.info(
                "Initialized Datastore client",
                project_id=project_id,
                namespace=datastore_namespace or 'default',
                **self._log_context
            )
        except Exception as e:
            self.logger.critical(
                "Failed to initialize Datastore client",
                error=str(e),
                exc_info=True,
                **self._log_context
            )
            raise
        
        # Initialize Vertex AI processor if config provided
        self.vertex_processor = None
        if self.vertex_config.get('enabled', False):
            try:
                self.vertex_processor = VertexAIProcessor(
                    project_id=vertex_config['project_id'],
                    region=vertex_config['region'],
                    model_id=vertex_config['model_id'],
                    endpoint_id=vertex_config.get('endpoint_id')
                )
                self.logger.info(
                    "Initialized Vertex AI processor",
                    model_id=vertex_config['model_id'],
                    endpoint_id=vertex_config.get('endpoint_id'),
                    **self._log_context
                )
            except Exception as e:
                self.logger.error(
                    "Failed to initialize Vertex AI processor",
                    error=str(e),
                    config={
                        k: v for k, v in vertex_config.items()
                        if k not in ['service_account_key']  # Don't log sensitive info
                    },
                    exc_info=True,
                    **self._log_context
                )
                # Don't raise here to allow pipeline to work without Vertex AI
                # if it's not critical for the use case

    def transform_data(self, raw_data: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Transform raw data into the required format for Datastore and Vertex AI.
        
        Args:
            raw_data: Raw input data dictionary
            
        Returns:
            Tuple containing:
                - datastore_entity_dict: Data formatted for Datastore
                - vertex_ai_data_dict: Data formatted for Vertex AI
                
        Raises:
            ValueError: If required fields are missing or invalid
        """
        try:
            # Validate required fields
            required_fields = ['source_ip', 'destination_ip', 'protocol', 'payload_size']
            missing_fields = [f for f in required_fields if f not in raw_data]
            
            if missing_fields:
                raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")
            
            # Get timestamp (use current time if not provided)
            timestamp = raw_data.get('timestamp')
            if not timestamp:
                timestamp = datetime.utcnow().isoformat()
                self.logger.debug(
                    "Using current time for missing timestamp",
                    **self._log_context
                )
            
            # Prepare Datastore entity with proper typing
            datastore_data = {
                'timestamp': timestamp,
                'source_ip': str(raw_data['source_ip']),
                'destination_ip': str(raw_data['destination_ip']),
                'protocol': str(raw_data['protocol']).upper(),
                'payload_size': int(raw_data['payload_size']),
                'processed_at': datetime.utcnow().isoformat(),
                'source': 'data_pipeline',
                'raw_data': json.dumps(raw_data)  # Store serialized original data
            }
            
            # Add any additional fields from raw_data (excluding None values)
            for key, value in raw_data.items():
                if key not in datastore_data and value is not None:
                    datastore_data[key] = value
            
            # Prepare Vertex AI features
            vertex_data = {
                'source_ip': str(raw_data['source_ip']),
                'destination_ip': str(raw_data['destination_ip']),
                'protocol': str(raw_data['protocol']).upper(),
                'payload_size': int(raw_data['payload_size']),
                'timestamp': timestamp
            }
            
            # Add threat score if available
            if 'threat_score' in raw_data:
                vertex_data['threat_score'] = float(raw_data['threat_score'])
            
            self.logger.debug(
                "Data transformation completed",
                input_keys=list(raw_data.keys()),
                output_datastore_keys=list(datastore_data.keys()),
                output_vertex_keys=list(vertex_data.keys()),
                **self._log_context
            )
            
            return datastore_data, vertex_data
            
        except (ValueError, TypeError, KeyError) as e:
            self.logger.error(
                "Data transformation failed",
                error=str(e),
                input_type=type(raw_data).__name__,
                input_keys=list(raw_data.keys()) if isinstance(raw_data, dict) else [],
                exc_info=True,
                **self._log_context
            )
            raise ValueError(f"Data transformation error: {str(e)}") from e

    def ingest_to_datastore(self, data):
        """
        Ingest data into Google Cloud Datastore.
        
        Args:
            data: Transformed data for Datastore
            
        Returns:
            Key of the ingested Datastore entity
        """
        try:
            # Create entity
            key = self.datastore_client.key(self.datastore_kind)
            entity = datastore.Entity(key=key)
            entity.update(data)
            
            # Save to Datastore
            self.datastore_client.put(entity)
            
            self.logger.info(
                "Successfully ingested data to Datastore",
                entity_key=str(key),
                **self._log_context
            )
            
            return entity.key
            
        except Exception as e:
            self.logger.error(
                "Error ingesting data to Datastore",
                error=str(e),
                data=data,
                **self._log_context
            )
            raise

    def process_with_vertex_ai(self, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Process data with Vertex AI for threat detection.
        
        Args:
            data: Transformed data for Vertex AI prediction
            
        Returns:
            Dictionary containing prediction results and metadata, or None if processing is skipped
            
        Raises:
            VertexAIError: If there's an error communicating with Vertex AI
        """
        if not self.vertex_processor:
            self.logger.warning(
                "Vertex AI processor not initialized - skipping prediction",
                data_keys=list(data.keys()),
                **self._log_context
            )
            return None
        
        pubsub_topic = self.vertex_config.get('pubsub_topic')
        
        try:
            # Process data through Vertex AI and optionally publish to Pub/Sub
            result = self.vertex_processor.process_and_predict(
                data=data,
                pubsub_topic=pubsub_topic
            )
            
            self.logger.info(
                "Successfully processed with Vertex AI",
                model=self.vertex_processor.model_id,
                endpoint=self.vertex_processor.endpoint_id,
                prediction_keys=list(result.get('prediction', {}).keys()) if isinstance(result.get('prediction'), dict) else [],
                **self._log_context
            )
            
            return result
            
        except VertexAIError as e:
            self.logger.error(
                "Vertex AI processing failed",
                error=str(e),
                model=self.vertex_processor.model_id,
                endpoint=self.vertex_processor.endpoint_id,
                exc_info=True,
                **self._log_context
            )
            # Re-raise to allow caller to handle the error
            raise
            
        except Exception as e:
            # Catch any unexpected errors
            self.logger.critical(
                "Unexpected error in Vertex AI processing",
                error=str(e),
                error_type=type(e).__name__,
                model=self.vertex_processor.model_id,
                exc_info=True,
                **self._log_context
            )
            raise VertexAIError(f"Unexpected error in Vertex AI processing: {str(e)}") from e

    def process_batch(self, raw_data_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process a batch of raw data records through the pipeline.
        
        Args:
            raw_data_list: List of raw data dictionaries to process
            
        Returns:
            List of result dictionaries with processing status and references
            
        Raises:
            RuntimeError: If there's a critical error in the batch processing
        """
        if not raw_data_list:
            self.logger.warning(
                "Received empty batch, nothing to process",
                **self._log_context
            )
            return []
        
        batch_results = []
        success_count = 0
        error_count = 0
        
        # Log batch start
        self.logger.info(
            "Starting batch processing",
            batch_size=len(raw_data_list),
            vertex_ai_enabled=self.vertex_processor is not None,
            **self._log_context
        )
        
        for i, raw_data in enumerate(raw_data_list, 1):
            item_result = {
                'success': False,
                'datastore_key': None,
                'vertex_prediction': None,
                'error': None
            }
            
            try:
                # Step 1: Transform the data
                datastore_data, vertex_data = self.transform_data(raw_data)
                
                # Step 2: Ingest to Datastore
                datastore_key = self.ingest_to_datastore(datastore_data)
                item_result['datastore_key'] = datastore_key
                
                # Step 3: Process with Vertex AI if enabled
                if self.vertex_processor:
                    try:
                        prediction = self.process_with_vertex_ai(vertex_data)
                        item_result['vertex_prediction'] = prediction
                        
                        # Update Datastore with prediction results
                        if prediction and 'prediction' in prediction:
                            self._update_entity_with_prediction(datastore_key, prediction)
                    except VertexAIError as e:
                        # Log but don't fail the entire batch for Vertex AI errors
                        self.logger.warning(
                            "Skipping Vertex AI processing due to error",
                            error=str(e),
                            datastore_key=datastore_key,
                            **self._log_context
                        )
                
                # Mark as successful
                item_result['success'] = True
                success_count += 1
                
                # Log progress for large batches
                if i % 10 == 0 or i == len(raw_data_list):
                    self.logger.debug(
                        "Batch progress",
                        processed=i,
                        total=len(raw_data_list),
                        success_rate=f"{(i - error_count) / i * 100:.1f}%",
                        **self._log_context
                    )
                
            except Exception as e:
                error_count += 1
                error_msg = str(e)
                item_result['error'] = error_msg
                
                self.logger.error(
                    "Error processing data item",
                    error=error_msg,
                    error_type=type(e).__name__,
                    item_index=i - 1,
                    success_count=success_count,
                    error_count=error_count,
                    exc_info=isinstance(e, (ValueError, TypeError)),
                    **self._log_context
                )
            
            batch_results.append(item_result)
        
        # Log batch completion
        self.logger.info(
            "Batch processing completed",
            batch_size=len(raw_data_list),
            successful=success_count,
            failed=error_count,
            success_rate=f"{success_count / len(raw_data_list) * 100:.1f}%" if raw_data_list else 'N/A',
            **self._log_context
        )
        
        return batch_results

    def _update_entity_with_prediction(self, key, prediction):
        try:
            entity = self.datastore_client.get(key)
            if entity:
                entity['prediction'] = prediction
                self.datastore_client.put(entity)
                self.logger.info(
                    "Updated Datastore entity with prediction",
                    entity_key=str(key),
                    **self._log_context
                )
            else:
                self.logger.warning(
                    "Datastore entity not found for prediction update",
                    entity_key=str(key),
                    **self._log_context
                )
        except Exception as e:
            self.logger.error(
                "Failed to update Datastore entity with prediction",
                error=str(e),
                entity_key=str(key),
                **self._log_context
            )

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description='Process network attack data through pipeline'
    )
    parser.add_argument('--project_id', required=True, help='Google Cloud project ID')
    parser.add_argument('--datastore_kind', required=True, help='Datastore entity kind')
    parser.add_argument('--datastore_namespace', help='Datastore namespace')
    parser.add_argument('--vertex_config', help='Path to Vertex AI configuration JSON')
    parser.add_argument('--input_file', required=True, help='Path to input data file (JSON)')
    
    args = parser.parse_args()
    
    # Load Vertex AI config if provided
    vertex_config = None
    if args.vertex_config:
        with open(args.vertex_config, 'r') as f:
            vertex_config = json.load(f)
    
    # Initialize pipeline
    pipeline = DataPipeline(
        project_id=args.project_id,
        datastore_kind=args.datastore_kind,
        datastore_namespace=args.datastore_namespace,
        vertex_config=vertex_config
    )
    
    # Load input data
    with open(args.input_file, 'r') as f:
        raw_data_list = json.load(f)
    
    # Process the data
    results = pipeline.process_batch(raw_data_list)
    
    print(f"Processed {len(results)} items successfully")
