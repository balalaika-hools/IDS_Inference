from scapy.all import sniff
from scapy.plist import PacketList
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from src.circular_buffer import CircularBuffer
from src.sniffer import PacketSniffer
import src.utils as util
import uvicorn
from src.GFlowMeter.GFlowMeter import GFlow_Meter
from src.fusion_model import Fusion_Model
import torch
import glob
import os
import time  
from src.prettyJson import PrettyJSONResponse


# Load the Checkpoint
pth_files = glob.glob(os.path.join('Pretrained_Model', '*.pth'))
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
cp = torch.load(pth_files[0], map_location=torch.device(device))

# Load the model 
model = Fusion_Model(cp['input_size'], cp['hidden_size'], cp['num_layers'], 
                        cp['statistical_features_size'], cp['fc_layers_sizes'],
                        cp['n_classes'], cp['batch_norm'], cp['dropout'])


# Load configuration from config.yaml
config = util.load_config('config.yaml')

# Initialize API
app = FastAPI()

# Initialize circular buffer
circular_buffer = CircularBuffer(config['capture_interval'])  # Last 10 seconds

# Initialize and start the packet sniffer
sniffer = PacketSniffer(circular_buffer, interfaces=config['interfaces'])
sniffer.start()


# Define the API endpoint
@app.post('/detect')
def detect_intrusion():
    start_time = time.time()  # Start timing
    
    # Capture the .pcap
    capture = PacketList(circular_buffer.get_packets())
    gflow = GFlow_Meter(capture, config['sample_type'], config['target_sample_length'], 'C', config['padding_per_packet'])
    
    # Transform .pcap to tabular and statistical
    tabular_data, statistical_data, flow_descriptions, pcap_datetime = gflow.Get_Data() # flow_descriptions:[proto, src_ip, dst_ip, src_port, dst_port] || pcap_datetime: '2024-10-03 21:17:37'
    flow_descriptions = util.transform_flow_descriptions(flow_descriptions)

    # Check if there is traffic
    if len(tabular_data) == 0:
        execution_time = round(time.time() - start_time, 2)
        response = {
            'Verdict': 'Sniffer is Empty. There is no traffic or there are no protocols of interest (UDP, TCP, SCTP)',
            'Execution Time (seconds)': execution_time
        }
        return PrettyJSONResponse(content=response)
    
    # Get predictions
    predictions = model.predict(tabular_data, statistical_data, config['batch_size'])
    
    # Process Predictions
    threshold_exceeded, attack_details, total_flows = util.process_predictions(predictions, flow_descriptions,
                                                                               cp['classes'], config['detection_threshold'])
    
    # Prepare the final response
    execution_time = round(time.time() - start_time, 2)  # Calculate execution time

    if threshold_exceeded:
        num_attacks = len(attack_details)
        verdict = 'Attack Detected' if num_attacks == 1 else 'Attacks Detected'
        response = {
            'Verdict': verdict,
            'Total Flows': total_flows,
            'Attacks': attack_details,
            'Execution Time (seconds)': execution_time
        }
    else:
        response = {
            'Verdict': 'No malicious content detected',
            'Total Flows': total_flows,
            'Execution Time (seconds)': execution_time
        }
    
    return PrettyJSONResponse(content=response)
    



if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
#2024-10-03 22:42:13,273 INFO Note: NumExpr detected 12 cores but "NUMEXPR_MAX_THREADS" not set, so enforcing safe limit of 8.
#2024-10-03 22:42:13,274 INFO NumExpr defaulting to 8 threads.