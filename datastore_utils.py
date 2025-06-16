import subprocess
import json


def get_datastore_instance_status(project_id):
    """
    Identifies the active Google Cloud Datastore instance within a specified project.

    Args:
        project_id (str): The ID of the Google Cloud project.

    Returns:
        str: A message indicating whether a Datastore instance is active or not.
             Includes error messages if the gcloud CLI is not configured correctly or if no instance is found.
    """
    try:
        command = [
            "gcloud",
            "datastore",
            "instances",
            "list",
            "--project",
            project_id,
            "--format=json",
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        instances = json.loads(result.stdout)

        if instances:
            return f"Datastore instance is active in project {project_id}."
        else:
            return f"No Datastore instance is active in project {project_id}."

    except subprocess.CalledProcessError as e:
        if "command not found" in e.stderr:
            return "Error: gcloud CLI is not installed. Please install and configure it."
        elif "Could not fetch project resource" in e.stderr:
            return f"Error: Project {project_id} not found or you do not have access."
        else:
            return f"Error: An unexpected error occurred: {e.stderr}"
    except json.JSONDecodeError:
        return "Error: Could not decode gcloud output. Ensure gcloud is configured correctly."
    except Exception as e:
        return f"An unexpected error occurred: {str(e)}"


if __name__ == "__main__":
    project_id = "your-project-id"  # Replace with your actual project ID
    status = get_datastore_instance_status(project_id)
    print(status)