import logging
import json
import os
from data_pipeline import DataPipeline
from logging_utils import PipelineLogger

def create_test_data():
    """Create sample test data."""
    return [
        {
            'timestamp': '2025-06-13T02:09:30Z',
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'protocol': 'TCP',
            'payload_size': 1024
        },
        {
            'timestamp': '2025-06-13T02:09:31Z',
            'source_ip': '192.168.1.101',
            'destination_ip': '10.0.0.2',
            'protocol': 'UDP',
            'payload_size': 512
        }
    ]

def test_pipeline():
    """Test the data pipeline."""
    logger = PipelineLogger(log_name='pipeline_test')
    
    try:
        # Create test data
        test_data = create_test_data()
        
        # Save test data to file
        os.makedirs('test_data', exist_ok=True)
        with open('test_data/test_input.json', 'w') as f:
            json.dump(test_data, f, indent=2)
        
        logger.info(
            "Created test data file",
            file_path='test_data/test_input.json'
        )
        
        # Initialize pipeline
        pipeline = DataPipeline(
            project_id='your-project-id',
            datastore_kind='AttackData',
            datastore_namespace='attack_data',
            vertex_config={
                'project_id': 'your-project-id',
                'region': 'us-central1',
                'model_id': 'your-model-id'
            }
        )
        
        # Process test data
        results = pipeline.process_batch(test_data)
        
        logger.info(
            "Pipeline test completed",
            results=results
        )
        
        return True
        
    except Exception as e:
        logger.error(
            "Pipeline test failed",
            error=str(e)
        )
        raise

if __name__ == "__main__":
    test_pipeline()
