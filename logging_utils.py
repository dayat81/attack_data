import logging
import json
import os
from google.cloud import logging as cloud_logging
from datetime import datetime
import traceback

class PipelineLogger:
    def __init__(self, project_id=None, log_name='attack_data_pipeline'):
        """
        Initialize the pipeline logger.
        
        Args:
            project_id (str, optional): Google Cloud project ID for Cloud Logging
            log_name (str, optional): Name of the log
        """
        self.project_id = project_id
        self.log_name = log_name
        self.cloud_logger = None
        
        # Configure local logging
        self.local_logger = logging.getLogger('attack_data_pipeline')
        self.local_logger.setLevel(logging.INFO)
        
        # Create console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # Create formatter and add it to the handlers
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        ch.setFormatter(formatter)
        
        # Add handlers to logger
        self.local_logger.addHandler(ch)
        
        # Initialize Cloud Logging if project_id is provided
        if project_id:
            try:
                client = cloud_logging.Client(project=project_id)
                self.cloud_logger = client.logger(log_name)
            except Exception as e:
                self.local_logger.error(f"Failed to initialize Cloud Logging: {str(e)}")

    def log(self, level, message, **kwargs):
        """
        Log a message with optional structured data.
        
        Args:
            level (str): Logging level (INFO, WARNING, ERROR, etc.)
            message (str): Log message
            kwargs: Additional structured data to include in the log
        """
        try:
            # Create structured log entry
            log_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'message': message,
                **kwargs
            }
            
            # Log to local
            if level == 'INFO':
                self.local_logger.info(json.dumps(log_entry))
            elif level == 'WARNING':
                self.local_logger.warning(json.dumps(log_entry))
            elif level == 'ERROR':
                self.local_logger.error(json.dumps(log_entry))
            
            # Log to Cloud if configured
            if self.cloud_logger:
                self.cloud_logger.log_struct(log_entry, severity=level)
                
        except Exception as e:
            # Always log errors to local
            self.local_logger.error(f"Error logging message: {str(e)}")
            self.local_logger.error(f"Original message: {message}")

    def error(self, message, exception=None, **kwargs):
        """
        Log an error with optional exception details.
        
        Args:
            message (str): Error message
            exception (Exception, optional): Exception object
            kwargs: Additional structured data to include in the log
        """
        try:
            # Add exception details if provided
            if exception:
                kwargs['exception_type'] = type(exception).__name__
                kwargs['exception_message'] = str(exception)
                kwargs['stack_trace'] = traceback.format_exc()
            
            self.log('ERROR', message, **kwargs)
            
        except Exception as e:
            self.local_logger.error(f"Error logging error: {str(e)}")
            self.local_logger.error(f"Original error message: {message}")

    def warning(self, message, **kwargs):
        """
        Log a warning message.
        
        Args:
            message (str): Warning message
            kwargs: Additional structured data to include in the log
        """
        self.log('WARNING', message, **kwargs)

    def info(self, message, **kwargs):
        """
        Log an info message.
        
        Args:
            message (str): Info message
            kwargs: Additional structured data to include in the log
        """
        self.log('INFO', message, **kwargs)
