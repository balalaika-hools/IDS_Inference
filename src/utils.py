import logging
import yaml
from collections import Counter
import ast


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)



# Load configuration from config.yaml
def load_config(config_path):
    with open(config_path, 'r') as file:
        config = yaml.safe_load(file)
    return config




def process_predictions(predictions, flow_descriptions, classes, detection_threshold):
    # Invert the class mapping
    index_to_class = {v: k for k, v in classes.items()}
    
    total_flows = len(predictions)
    
    # Get nominal class index
    nominal_index = classes['Nominal']
    
    # Collect malicious flows exceeding the threshold
    class_counts = Counter(predictions)
    threshold_exceeded = False
    attack_details = []
    
    for class_index, count in class_counts.items():
        if class_index != nominal_index and (count / total_flows) >= detection_threshold:
            threshold_exceeded = True
            class_name = index_to_class[class_index]
            
            # Get indices of malicious flows
            indices = [i for i, pred in enumerate(predictions) if pred == class_index]
            attack_flows = [flow_descriptions[i] for i in indices]
            
            # Extract protocols, src/dest IPs and ports
            protocols = set()
            src_ips = set()
            dst_ips = set()
            src_ports = set()
            dst_ports = set()
            
            for flow in attack_flows:
                proto, src_ip, dst_ip, src_port, dst_port = flow
                protocols.add(proto)
                src_ips.add(src_ip)
                dst_ips.add(dst_ip)
                src_ports.add(src_port)
                dst_ports.add(dst_port)
            
            attack_info = {
                'Attack Name': class_name,
                'Number of Flows': count,
                'Protocols': list(protocols),
                'Source IPs': list(src_ips),
                'Destination IPs': list(dst_ips),
                'Source Ports': list(src_ports),
                'Destination Ports': list(dst_ports)
            }
            attack_details.append(attack_info)
            
    return threshold_exceeded, attack_details, total_flows



def transform_flow_descriptions(flow_descriptions):
    # Convert each flow description from string to list
    processed_flow_descriptions = []
    for flow_str in flow_descriptions:
        try:
            flow = ast.literal_eval(flow_str)
            processed_flow_descriptions.append(flow)
        except (SyntaxError, ValueError) as e:
            # Handle parsing errors if necessary
            continue  # Skip this flow if it can't be parsed

    # Replace the original flow_descriptions with the processed one
    flow_descriptions = processed_flow_descriptions
    return flow_descriptions