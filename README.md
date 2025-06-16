# Network Attack Data Pipeline

## Overview

This repository implements a pipeline for streaming network attack data to Google Cloud for threat detection using Vertex AI. The pipeline includes:

- Data ingestion to Google Cloud Datastore
- Real-time threat detection using Vertex AI
- Comprehensive monitoring and alerting
- Structured logging
- Automated cleanup and lifecycle management

## Requirements

- Python 3.9+
- Google Cloud SDK
- Google Cloud project with enabled APIs:
  - Datastore API
  - Vertex AI API
  - Cloud Logging API
  - Pub/Sub API

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Configure Google Cloud credentials:
```bash
export GOOGLE_APPLICATION_CREDENTIALS="path/to/your/service-account.json"
export PROJECT_ID="your-project-id"
```

3. Enable required APIs:
```bash
./deploy.sh enable-apis
```

## Pipeline Components

### 1. Data Ingestion
- `data_pipeline.py`: Core pipeline implementation
- `datastore_instance_checker.py`: Verifies Datastore instance status
- `logging_utils.py`: Provides structured logging

### 2. Threat Detection
- `vertex_ai_utils.py`: Vertex AI integration
- Handles real-time predictions
- Supports batch processing

### 3. Monitoring & Alerting
- Cloud Monitoring dashboard
- Cloud Alerting policies
- Cloud Logging integration

## Configuration

### Vertex AI Configuration
```json
{
    "project_id": "your-project-id",
    "region": "us-central1",
    "model_id": "your-model-id"
}
```

### Environment Variables
```bash
export GOOGLE_APPLICATION_CREDENTIALS="path/to/your/service-account.json"
export PROJECT_ID="your-project-id"
```

## Usage

### Verify Datastore Instance
```bash
python datastore_instance_checker.py \
    --project_id your-project-id \
    --instance_id your-instance-id
```

### Process Data
```bash
python data_pipeline.py \
    --project_id your-project-id \
    --datastore_kind AttackData \
    --datastore_namespace attack_data \
    --vertex_config vertex_config.json \
    --input_file path/to/your/data.json
```

### Run Tests
```bash
python test_pipeline.py
```

## Monitoring

### Cloud Dashboard
- Data ingestion rate
- Vertex AI prediction latency
- Error rates
- Datastore operations
- Pipeline health

### Alerting
- Low data ingestion rate
- High prediction latency
- High error rate

## Documentation

- [Configuration Guide](docs/configuration.md)
- [Implementation Details](docs/pipeline_implementation.md)
- [Troubleshooting Guide](docs/troubleshooting.md)

## Security

- IAM permissions are configured automatically
- Data is encrypted at rest and in transit
- Automated cleanup policies are in place
- Security Command Center integration

## License

MIT License - see LICENSE file for details

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## Support

For support, please open an issue in the repository.
|---|---|
| id | UUID of dataset |
|name  | name of author  |
| date  | last modified date  |
| dataset  | array of URLs where the hosted version of the dataset is located  |
| description | describes the dataset as detailed as possible |
| environment |  markdown filename of the environment description see below |
| technique | array of MITRE ATT&CK techniques associated with dataset |
| references | array of URLs that reference the dataset |
| sourcetypes | array of sourcetypes that are contained in the dataset |


For example

```
id: 405d5889-16c7-42e3-8865-1485d7a5b2b6
author: Patrick Bareiss
date: '2020-10-08'
description: 'Atomic Test Results: Successful Execution of test T1003.001-1 Windows
  Credential Editor Successful Execution of test T1003.001-2 Dump LSASS.exe Memory
  using ProcDump Return value unclear for test T1003.001-3 Dump LSASS.exe Memory using
  comsvcs.dll Successful Execution of test T1003.001-4 Dump LSASS.exe Memory using
  direct system calls and API unhooking Return value unclear for test T1003.001-6
  Offline Credential Theft With Mimikatz Return value unclear for test T1003.001-7
  LSASS read with pypykatz '
environment: attack_range
technique:
- T1003.001
dataset:
- https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-powershell.log
- https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-security.log
- https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log
- https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-system.log
references:
- https://attack.mitre.org/techniques/T1003/001/
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md
- https://github.com/splunk/security-content/blob/develop/tests/T1003_001.yml
sourcetypes:
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
- WinEventLog:Microsoft-Windows-PowerShell/Operational
- WinEventLog:System
- WinEventLog:Security
```


### Environments

Environments are a description of where the dataset was collected. At this moment there are no specific restrictions, although we do have a simple [template](https://github.com/splunk/attack_data/blob/master/environments/TEMPLATE.md) a user can start with here. The most common environment for most datasets will be the [attack_range](https://github.com/splunk/attack_data/blob/master/environments/attack_range.md) since this is the tool that used to generate attack data sets automatically.

# Replay Datasets 📼
Most datasets generated will be raw log files. There are two main simple ways to ingest it.

### Into Splunk


##### using replay.py
pre-requisite, clone, create virtual env and install python deps:

```
git clone git@github.com:splunk/attack_data.git
cd attack_data
pip install virtualenv
virtualenv venv
source venv/bin/activate
pip install -r bin/requirements.txt
```

0. Download dataset 
1. configure [`bin/replay.yml`](/bin/replay.yml) 
2. run `python bin/replay.py -c bin/replay.yml`


##### using UI

0. Download dataset
1. In Splunk enterprise , add data -> Files & Directories -> select dataset
2. Set the sourcetype as specified in the YML file
3. Explore your data

See a quick demo 📺 of this process [here](https://www.youtube.com/watch?v=41NAG0zGg40).

### Into DSP

To send datasets into DSP the simplest way is to use the [scloud](https://docs.splunk.com/Documentation/DSP/1.1.0/Admin/AuthenticatewithSCloud) command-line-tool as a requirement.

1. Download the dataset
2. Ingest the dataset into DSP via scloud command `cat attack_data.json | scloud ingest post-events --format JSON
3. Build a pipeline that reads from the firehose and you should see the events.

# Contribute Datasets 🥰

1. Generate a dataset
2. Under the corresponding MITRE Technique ID folder create a folder named after the tool the dataset comes from, for example: `atomic_red_Team`
3. Make PR with <tool_name_yaml>.yml file under the corresponding created folder, upload dataset into the same folder.

See [T1003.002](datasets/attack_techniques/T1003.003/atomic_red_team/) for a complete example.

Note the simplest way to generate a dataset to contribute is to launch your simulations in the attack_range, or manually attack the machines and when done dump the data using the [dump function](https://github.com/splunk/attack_range#dump-log-data-from-attack-range).

See a quick demo 📺 of the process to dump a dataset [here](https://www.youtube.com/watch?v=CnD0BtjCILs).

To contribute a dataset simply create a PR on this repository, for general instructions on creating a PR [see this guide](https://gist.github.com/Chaser324/ce0505fbed06b947d962).

# Automatically generated Datasets ⚙️

This project takes advantage of automation to generate datasets using the attack_range. You can see details about this service on this [sub-project folder attack_data_service](https://github.com/splunk/attack_data/tree/master/attack_data_service).

## Author
* [Patrick Bareiß](https://twitter.com/bareiss_patrick)
* [Jose Hernandez](https://twitter.com/d1vious)


## License

Copyright 2023 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
