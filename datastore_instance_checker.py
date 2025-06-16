import logging
import os
from google.cloud import datastore
from logging_utils import PipelineLogger

class DatastoreInstanceChecker:
    def __init__(self, project_id, datastore_instance_id=None):
        """
        Initialize the Datastore instance checker.
        
        Args:
            project_id (str): Google Cloud project ID
            datastore_instance_id (str, optional): Specific Datastore instance ID
        """
        self.project_id = project_id
        self.datastore_instance_id = datastore_instance_id
        self.logger = PipelineLogger(project_id, log_name='datastore_instance_checker')

    def verify_instance(self):
        """
        Verify the Datastore instance is active and accessible.
        
        Returns:
            tuple: (bool, str) - (is_active, instance_details)
        """
        try:
            # Initialize Datastore client
            client = datastore.Client(project=self.project_id)
            
            # Check if client can connect
            try:
                # Attempt a simple operation to verify connection
                query = client.query(kind='_Kind')
                query.keys_only()
                list(query.fetch(limit=1))
                
                self.logger.info(
                    "Successfully connected to Datastore",
                    project_id=self.project_id
                )
                
                return True, {
                    'project_id': self.project_id,
                    'instance_id': self.datastore_instance_id,
                    'status': 'active'
                }
                
            except Exception as e:
                self.logger.error(
                    "Failed to connect to Datastore",
                    error=str(e)
                )
                return False, {
                    'project_id': self.project_id,
                    'instance_id': self.datastore_instance_id,
                    'status': 'inactive',
                    'error': str(e)
                }
                
        except Exception as e:
            self.logger.error(
                "Error during Datastore verification",
                error=str(e)
            )
            return False, {
                'project_id': self.project_id,
                'instance_id': self.datastore_instance_id,
                'status': 'error',
                'error': str(e)
            }

    def document_instance_details(self, instance_details):
        """
        Document the instance details to a file.
        
        Args:
            instance_details (dict): Details about the Datastore instance
        """
        try:
            # Create documentation directory if it doesn't exist
            doc_dir = 'docs'
            os.makedirs(doc_dir, exist_ok=True)
            
            # Write instance details to file
            with open(f'{doc_dir}/datastore_instance_details.txt', 'w') as f:
                for key, value in instance_details.items():
                    f.write(f"{key}: {value}\n")
            
            self.logger.info(
                "Documented Datastore instance details",
                file_path=f'{doc_dir}/datastore_instance_details.txt'
            )
            
        except Exception as e:
            self.logger.error(
                "Error documenting instance details",
                error=str(e)
            )
            raise

if __name__ == "__main__":
    # Example usage
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Verify and document Google Cloud Datastore instance'
    )
    parser.add_argument('--project_id', required=True, help='Google Cloud project ID')
    parser.add_argument('--instance_id', help='Datastore instance ID')
    
    args = parser.parse_args()
    
    checker = DatastoreInstanceChecker(args.project_id, args.instance_id)
    is_active, details = checker.verify_instance()
    
    if is_active:
        checker.document_instance_details(details)
    else:
        print(f"Datastore instance verification failed: {details['error']}")
