# IDS_Inference

## Introduction

IDS_Inference is a real-time Intrusion Detection System (IDS) designed to monitor network traffic and detect malicious activities using a pre-trained deep learning model. The system captures live network packets, processes them to extract relevant features, and then performs inference using a fusion model to determine if any intrusion has occurred. The application exposes a RESTful API built with FastAPI, allowing users to trigger detection and receive results in JSON format.


## Features

- **Real-Time Packet Capturing**: Uses Scapy to capture live network traffic.
- **Feature Extraction**: Implements GFlowMeter for flow-based feature extraction.
- **Deep Learning Inference**: Utilizes a pre-trained PyTorch fusion model for intrusion detection.
- **RESTful API**: Exposes endpoints via FastAPI for easy integration and automation.
- **Flexible Deployment**: Can run locally or inside a Docker container.

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
  - [Local Setup](#local-setup)
  - [Docker Setup](#docker-setup)
- [Usage](#usage)
  - [Running Locally](#running-locally)
  - [Running with Docker](#running-with-docker)
- [Testing](#testing)
  - [Testing Locally](#testing-locally)
  - [Testing with Docker](#testing-with-docker)
- [Configuration](#configuration)
- [Project Structure](#project-structure)


## Requirements

### Hardware Requirements

- **Operating System**: Linux or macOS (Windows support may be limited due to network capturing requirements).
- **Privileges**: Root or administrator privileges are required for packet capturing.
- **Optional**: GPU for accelerated inference (if available).

### Software Requirements

- **Python**: Version 3.9 or higher.
- **Docker**: If you choose to run the application inside a Docker container.

### Python Dependencies

All Python dependencies are listed in the `requirements.txt` file:

- `fastapi`
- `uvicorn[standard]`
- `PyYAML`
- `numpy`
- `pandas`
- `hexdump`
- `scapy`
- `torch` (installed separately for compatibility)

### System Dependencies

- `tcpdump`
- `libpcap-dev`
- `build-essential`

These are required for Scapy to capture packets and build certain dependencies.

## Installation

### Local Setup

#### Step 1: Install System Dependencies

**For Debian/Ubuntu-based systems:**

```bash
sudo apt-get update
sudo apt-get install -y tcpdump libpcap-dev build-essential
```

**For macOS:**

```bash
brew install libpcap
```

#### Step 2: Clone the Repository

```bash
git clone https://github.com/balalaika-hools/IDS_Inference.git
cd IDS_Inference
```

#### Step 3: Set Up a Python Virtual Environment (Optional but Recommended)

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows use venv\Scripts\activate
```

#### Step 4: Install Python Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

#### Step 5: Install PyTorch

**For CPU-only support:**

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
```

**For GPU support:**

Visit [PyTorch Get Started](https://pytorch.org/get-started/locally/) and follow the instructions to install the version compatible with your CUDA setup.

#### Step 6: Verify Installation

```bash
python -c "import torch; print('PyTorch version:', torch.__version__)"
python -c "import scapy; print('Scapy version:', scapy.__version__)"
```

### Docker Setup

#### Prerequisites

- **Docker**: Ensure Docker is installed and running on your system.

#### Step 1: Build the Docker Image

```bash
docker build -t ids_inference:latest .
```

This command builds a Docker image named `ids_inference` using the `Dockerfile` provided.

#### Step 2: Verify the Docker Image

```bash
docker images | grep ids_inference
```

You should see an entry for `ids_inference` in the list of Docker images.

## Usage

### Running Locally

#### Step 1: Start the Application

**Note**: Root privileges are required for packet capturing.

```bash
sudo python app.py
```

This will start the FastAPI application on `http://0.0.0.0:8000`.

#### Step 2: Access the API Documentation (Optional)

Open a web browser and navigate to:

```
http://0.0.0.0:8000/docs
```

This will display the automatically generated API documentation provided by FastAPI.

#### Step 3: Trigger Detection

Use `curl` or any HTTP client to send a POST request to the `/detect` endpoint:

```bash
curl -X POST http://0.0.0.0:8000/detect
```

You should receive a JSON response indicating whether an intrusion was detected.

### Running with Docker

#### Step 1: Run the Docker Container

**Important**: The container needs access to network interfaces and certain capabilities to capture packets.

```bash
docker run --rm -it \
  --net=host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  ids_inference:latest
```

- `--net=host`: Shares the host's networking stack.
- `--cap-add=NET_ADMIN` and `--cap-add=NET_RAW`: Grants necessary capabilities for packet capturing.

#### Step 2: Access the API

Since the container shares the host's network, the API is accessible at:

```
http://0.0.0.0:8000
```

#### Step 3: Trigger Detection

```bash
curl -X POST http://0.0.0.0:8000/detect
```

## Testing

### Testing Locally

#### Generate Network Traffic

To test the IDS, you can generate various types of network traffic:

- **Normal Traffic**: Browse the internet, stream videos, or perform regular network activities.
- **Malicious Traffic**: Use tools like `nmap`, `hping3`, or custom scripts to simulate attacks.


#### Check Detection Results

After generating traffic, send a POST request to the `/detect` endpoint:

```bash
curl -X POST http://0.0.0.0:8000/detect
```

Review the JSON response to see if any intrusions were detected.

### Testing with Docker

Testing within the Docker container follows the same steps as local testing. Ensure that the container has the necessary permissions and network access as specified in the [Running with Docker](#running-with-docker) section.

## Configuration

The application uses a `config.yaml` file located in the root directory for configuration parameters.

```yaml
# GFlowMeter Parameters
capture_interval: 1                   # Traffic capture interval in seconds
sample_type: 'bidirectional'          # 'bidirectional' or 'unidirectional' flows
target_sample_length: 1024            # Number of bytes to keep per flow
padding_per_packet: False             # Pad each packet uniformly until target sample length

# Capture Parameters
interfaces:
  - 'Ethernet'                        # List of network interfaces to capture from

# Model Parameters
batch_size: 32                        # Batch size for model inference
detection_threshold: 0.1              # Detection threshold (0 < detection_threshold <= 1)
```

### Adjusting Parameters

- **`capture_interval`**: Increase to capture more data per detection cycle.
- **`sample_type`**: Choose between 'bidirectional' and 'unidirectional' flow analysis.
- **`interfaces`**: Specify the network interfaces to monitor. Use `ifconfig` or `ip addr` to list available interfaces.
- **`detection_threshold`**: Lowering this value makes the IDS more sensitive.

### Changing Network Interface

To change the network interface the IDS monitors, edit the `interfaces` section:

```yaml
interfaces:
  - 'eth0'    # Replace 'eth0' with your desired interface name
```

## Project Structure

```
IDS_Inference/
├── app.py                        # Main application script
├── config.yaml                   # Configuration file
├── Dockerfile                    # Docker build file
├── requirements.txt              # Python dependencies
├── Pretrained_Model/             # Directory containing the pre-trained model
│   └── model.pth                 # Pre-trained PyTorch model file
├── src/                          # Source code directory
    ├── circular_buffer.py        # Circular buffer implementation
    ├── sniffer.py                # Packet sniffer implementation
    ├── utils.py                  # Utility functions
    ├── fusion_model.py           # Model architecture and prediction methods
    ├── prettyJson.py             # Custom JSON response class
    └── GFlowMeter/               # GFlowMeter module for feature extraction
        ├── GFlowMeter.py         # GFlowMeter implementation
        ├── Bi_Feature_Names.txt  # Feature names for bidirectional flows
        └── Uni_Feature_Names.txt # Feature names for unidirectional flows
```

### Key Components

- **`app.py`**: Initializes the FastAPI app, starts the packet sniffer, and defines the `/detect` endpoint.
- **`circular_buffer.py`**: Implements a thread-safe circular buffer to store recent packets.
- **`sniffer.py`**: Defines the packet sniffer that captures packets from specified interfaces.
- **`fusion_model.py`**: Contains the PyTorch model class and prediction method.
- **`GFlowMeter`**: Module responsible for extracting features from network flows.




---

