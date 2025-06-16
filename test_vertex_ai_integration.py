#!/usr/bin/env python3
"""
Test script for Vertex AI integration with the attack data pipeline.
"""
import json
import os
import sys
import argparse
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data_pipeline import DataPipeline
from vertex_ai_utils import VertexAIProcessor

def generate_test_data(count: int = 5) -> List[Dict[str, Any]]:
    """Generate test network traffic data."""
    base_time = datetime.utcnow()
    protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS']
    
    data = []
    for i in range(count):
        timestamp = (base_time - timedelta(seconds=i*10)).isoformat()
        data.append({
            'timestamp': timestamp,
            'source_ip': f'192.168.1.{i+1}',
            'destination_ip': '10.0.0.1',
            'protocol': protocols[i % len(protocols)],
            'payload_size': (i + 1) * 100,
            'threat_score': min(0.9, i * 0.2),  # Varying threat scores
            'additional_info': f'Test data item {i+1}'
        })
    return data

def test_vertex_ai_processor(config_path: str, test_data: List[Dict[str, Any]]):
    """Test the VertexAIProcessor with sample data."""
    print("\n=== Testing VertexAIProcessor ===")
    
    # Load config
    with open(config_path) as f:
        config = json.load(f)
    
    # Initialize processor
    processor = VertexAIProcessor(
        project_id=config['project_id'],
        region=config['region'],
        model_id=config['model_id'],
        endpoint_id=config.get('endpoint_id')
    )
    
    # Test with each data item
    for i, data in enumerate(test_data, 1):
        print(f"\n--- Test Item {i} ---")
        print(f"Input: {json.dumps(data, indent=2, default=str)}")
        
        try:
            # Test prediction
            print("\nSending to Vertex AI...")
            result = processor.process_and_predict(
                data=data,
                pubsub_topic=config.get('pubsub_topic')
            )
            
            print("\nPrediction Result:")
            print(json.dumps(result, indent=2, default=str))
            
        except Exception as e:
            print(f"Error: {str(e)}")
            import traceback
            traceback.print_exc()

def test_data_pipeline(config_path: str, test_data: List[Dict[str, Any]]):
    """Test the full data pipeline with Vertex AI integration."""
    print("\n=== Testing DataPipeline with Vertex AI ===")
    
    # Load config
    with open(config_path) as f:
        config = json.load(f)
    
    # Initialize pipeline
    pipeline = DataPipeline(
        project_id=config['project_id'],
        datastore_kind='AttackData',
        datastore_namespace='attack_data',
        vertex_config={
            'enabled': True,
            'project_id': config['project_id'],
            'region': config['region'],
            'model_id': config['model_id'],
            'endpoint_id': config.get('endpoint_id'),
            'pubsub_topic': config.get('pubsub_topic')
        }
    )
    
    # Process test data
    print(f"Processing {len(test_data)} items...")
    results = pipeline.process_batch(test_data)
    
    # Print results
    print("\nProcessing Results:")
    for i, result in enumerate(results, 1):
        status = "SUCCESS" if result.get('success') else "FAILED"
        error = result.get('error', 'None')
        print(f"Item {i}: {status}")
        print(f"  Datastore Key: {result.get('datastore_key')}")
        print(f"  Error: {error}")
        
        if 'vertex_prediction' in result and result['vertex_prediction']:
            pred = result['vertex_prediction'].get('prediction', {})
            print(f"  Prediction: {json.dumps(pred, default=str, indent=4)}")

def main():
    parser = argparse.ArgumentParser(description='Test Vertex AI integration')
    parser.add_argument('--config', type=str, default='vertex_config.json',
                      help='Path to Vertex AI configuration file')
    parser.add_argument('--count', type=int, default=3,
                      help='Number of test items to generate')
    parser.add_argument('--test', type=str, choices=['all', 'processor', 'pipeline'], default='all',
                      help='Which test to run')
    
    args = parser.parse_args()
    
    # Generate test data
    test_data = generate_test_data(args.count)
    
    # Run selected tests
    try:
        if args.test in ['all', 'processor']:
            test_vertex_ai_processor(args.config, test_data)
        
        if args.test in ['all', 'pipeline']:
            test_data_pipeline(args.config, test_data)
            
        print("\n=== Tests completed successfully ===")
        
    except Exception as e:
        print(f"\n=== Test failed: {str(e)} ===")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
