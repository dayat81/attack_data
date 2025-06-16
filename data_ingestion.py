import argparse
import json
import csv
import logging
from google.cloud import datastore
from datastore_utils import get_datastore_instance_status
from vertex_ai_utils import VertexAIProcessor

def ingest_data(input_file, datastore_kind, datastore_namespace, project_id, log_file, vertex_project_id=None, vertex_region=None, vertex_model_id=None, pubsub_topic=None):
    """
    Ingests data from a JSON or CSV file into Google Cloud Datastore and processes it with Vertex AI.
    
    Args:
        input_file (str): Path to the input data file
        datastore_kind (str): Datastore entity kind
        datastore_namespace (str): Datastore namespace
        project_id (str): Google Cloud project ID
        log_file (str): Path to log file
        vertex_project_id (str, optional): Vertex AI project ID
        vertex_region (str, optional): Vertex AI region
        vertex_model_id (str, optional): Vertex AI model ID
        pubsub_topic (str, optional): Pub/Sub topic for real-time processing
    """
    # Configure logging
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    try:
        # Verify Datastore instance status
        if not get_datastore_instance_status(project_id):
            logging.error("Datastore instance is not active. Exiting.")
            return

        # Create a Datastore client
        client = datastore.Client(project=project_id, namespace=datastore_namespace)

        # Determine file type and read data
        if input_file.endswith(".json"):
            with open(input_file, "r") as f:
                data = json.load(f)
        elif input_file.endswith(".csv"):
            with open(input_file, "r") as f:
                reader = csv.DictReader(f)
                data = list(reader)
        else:
            logging.error("Unsupported file format. Please use JSON or CSV.")
            return

        # Initialize Vertex AI processor if parameters are provided
        vertex_processor = None
        if vertex_project_id and vertex_region and vertex_model_id:
            try:
                vertex_processor = VertexAIProcessor(vertex_project_id, vertex_region, vertex_model_id)
            except Exception as e:
                logging.error(f"Failed to initialize Vertex AI processor: {str(e)}")

        # Prepare Datastore entities and process with Vertex AI
        entities = []
        for item in data:
            # Create Datastore entity
            key = client.key(datastore_kind)
            entity = datastore.Entity(key=key)
            entity.update(item)
            entities.append(entity)

            # Process with Vertex AI if initialized
            if vertex_processor:
                try:
                    # Process data with Vertex AI
                    prediction = vertex_processor.send_to_vertex_ai(item)
                    logging.info(f"Vertex AI prediction: {prediction}")

                    # Publish to Pub/Sub if topic is provided
                    if pubsub_topic:
                        vertex_processor.publish_to_pubsub(pubsub_topic, item)
                        logging.info(f"Published to Pub/Sub topic: {pubsub_topic}")
                except Exception as e:
                    logging.error(f"Error processing with Vertex AI: {str(e)}")

        # Ingest data into Datastore in batches
        try:
            with client.transaction():
                client.put_multi(entities)
            logging.info(f"Successfully ingested {len(entities)} records into Datastore")
        except Exception as e:
            logging.error(f"Error ingesting data into Datastore: {str(e)}")
            raise

        logging.info(f"Successfully ingested {len(entities)} entities into Datastore.")

        print(f"Successfully ingested {len(entities)} entities into Datastore.")

    except Exception as e:
        logging.error(f"An error occurred during data ingestion: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Ingest data into Google Cloud Datastore."
    )
    parser.add_argument(
        "--input_file", required=True, help="Path to the input JSON or CSV file."
    )
    parser.add_argument(
        "--datastore_kind", required=True, help="The Datastore kind to use."
    )
    parser.add_argument(
        "--datastore_namespace",
        required=True,
        help="The Datastore namespace to use.",
    )
    parser.add_argument(
        "--project_id", required=True, help="The Google Cloud project ID."
    )
    parser.add_argument(
        "--log_file", required=True, help="Path to the log file."
    )
    parser.add_argument(
        "--vertex_project_id", help="Vertex AI project ID."
    )
    parser.add_argument(
        "--vertex_region", help="Vertex AI region."
    )
    parser.add_argument(
        "--vertex_model_id", help="Vertex AI model ID."
    )

    args = parser.parse_args()

    ingest_data(
        args.input_file,
        args.datastore_kind,
        args.datastore_namespace,
        args.project_id,
        args.log_file,
        args.vertex_project_id,
        args.vertex_region,
        args.vertex_model_id,
    )