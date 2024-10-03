import warnings, logging, os, hexdump
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
warnings.simplefilter("ignore", DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning, message="No IPv4 address found on .*")
import scapy.all
import pandas as pd
import numpy as np
import datetime
from sys import platform
if platform == 'darwin' or platform == 'linux1' or platform == 'linux2':
    from scapy.config import conf
    conf.use_pcap = True

'''
A: Tabular
B: Statistical
C: Tabular + Statistical
'''

class GFlow_Meter():
    def __init__(self, capture,  sample_type='bidirectional', target_sample_length=784,
                dataset_type='C', padding_per_packet=False):

        self.capture = capture
        
        # Save Parameters
        self.dataset_type = dataset_type
        self.sample_type = sample_type
        self.target_sample_length = target_sample_length
        self.padding_per_packet = padding_per_packet

        # Check Dataset Type
        valid_dataset_types= {'A', 'B', 'C'}
        if self.dataset_type not in valid_dataset_types:
            raise Exception("Wrong Dataset Type. Try 'A', 'B' or 'C'")

        # Check Flow-Types
        if self.sample_type!= 'unidirectional' and self.sample_type!= 'bidirectional':
            raise Exception("Wrong Sample Type. Try 'unidirectional' or 'bidirectional'")

        # Layers Setup
        self.tcp_layer = scapy.layers.inet.TCP
        self.udp_layer = scapy.layers.inet.UDP
        self.sctp_layer = scapy.layers.sctp.SCTP

        # Read Statistical Features
        self.feature_names = []
        feature_names_path = 'src/GFlowMeter/Bi_Feature_Names.txt' if sample_type == 'bidirectional' else 'src/GFlowMeter/Uni_Feature_Names.txt'
        with open(os.path.join(os.getcwd(), feature_names_path)) as file:
            self.feature_names = [line.rstrip() for line in file]
        self.df_statistical = pd.DataFrame(columns=self.feature_names, dtype=float)
            
            
            

    def Get_Data(self):
        # Capture Flows 
        self.Capture_Flows()
        
        # Get Tabular Data
        tabular_data, flow_descriptions, pcap_datetime = self.Get_Hex_Flows(self.capture)
        if len(flow_descriptions) == 0: return [], [], [], [], []
        tabular_data = np.array(tabular_data).astype(np.float32)
        
        # Get Statistical Data
        statistical_data = self.Get_Statitstical_Features(self.capture)
        statistical_data = statistical_data.to_numpy().astype(np.float32)
        
        return tabular_data, statistical_data, flow_descriptions, pcap_datetime
        
        


    def Capture_Flows(self):
        if self.sample_type == 'unidirectional':
            self.capture = self.capture.sessions(self.Unidirectional_Flows_Split)
        elif self.sample_type == 'bidirectional':
            self.capture = self.capture.sessions(self.Bidirectional_Sessions_Split)
        else:
            raise Exception("PROVIDED sample_type IS INVALID")
        
   
        
        
    def Unidirectional_Flows_Split(self, packet):
        ip_layer = scapy.layers.inet.IP if 'IP' in packet else scapy.layers.inet6.IPv6
        if ('IP' in packet) or ('IPv6' in packet):
            if 'TCP' in packet:
                sess = str(['TCP', packet[ip_layer].src, packet[self.tcp_layer].sport,
                            packet[ip_layer].dst, packet[self.tcp_layer].dport])
            elif 'UDP' in packet:
                sess = str(['UDP', packet[ip_layer].src, packet[self.udp_layer].sport,
                            packet[ip_layer].dst, packet[self.udp_layer].dport])

            elif 'SCTP' in packet:
                sess = str(['SCTP', packet[ip_layer].src, packet[self.sctp_layer].sport,
                            packet[ip_layer].dst, packet[self.sctp_layer].sport])
            else:
                sess = str(['IP_Based_Sorted', packet[ip_layer].src, packet[ip_layer].dst])
        else:
            sess = packet.sprintf("No_IPv4_or_IPV6 --> Ethernet type=%04xr,Ether.type%")
        return sess




    def Bidirectional_Sessions_Split(self, packet):
        ip_layer = scapy.layers.inet.IP if 'IP' in packet else scapy.layers.inet6.IPv6
        if ('IP' in packet) or ('IPv6' in packet):
            if 'TCP' in packet:
                sess = str(['TCP'] + sorted([packet[ip_layer].src, str(packet[self.tcp_layer].sport),
                                             packet[ip_layer].dst, str(packet[self.tcp_layer].dport)],
                                            key=str))
            elif 'UDP' in packet:
                sess = str(['UDP'] + sorted([packet[ip_layer].src, str(packet[self.udp_layer].sport),
                                             packet[ip_layer].dst, str(packet[self.udp_layer].dport)],
                                            key=str))
            elif 'SCTP' in packet:
                sess = str(['SCTP'] + sorted([packet[ip_layer].src, str(packet[self.sctp_layer].sport),
                                              packet[ip_layer].dst, str(packet[self.sctp_layer].dport)],
                                             key=str))
            else:
                sess = str(['IP_Based_Sorted', packet[ip_layer].src, packet[ip_layer].dst])
        else:
            sess = packet.sprintf("No_IPv4_or_IPV6 --> Ethernet type=%04xr,Ether.type%")
        return sess
    
    
    
    def Get_Hex_Flows(self, capture):
        samples = []
        sessions_description = []
        get_datetime = False
        for packet_description, packet_list in capture.items():
            sample_packets = []
            if get_datetime is False:
                pcap_datetime = datetime.datetime.fromtimestamp(float(packet_list[0].time)).strftime('%Y-%m-%d %H:%M:%S')
                get_datetime = True
            if self.Check_For_Protocols(packet_description):
                sessions_description.append(packet_description)
                for packet in packet_list:
                    processed_packet = self.Process_Packet(packet)
                    sample_packets += processed_packet
            else:
                continue
            sample_packets = self.Pad_Sample(sample_packets, self.target_sample_length)
            samples.append(sample_packets)
        return samples, sessions_description, pcap_datetime
    
    
    
    def Get_Packet_Description(self, packet):
        ip_layer = scapy.layers.inet.IP if 'IP' in packet else scapy.layers.inet6.IPv6
        src_ip = str(packet[ip_layer].src)
        dst_ip = str(packet[ip_layer].dst)
        src_port = str(packet.sport)
        dst_port = str(packet.dport)
        return [src_ip, dst_ip, src_port, dst_port]



    def Check_For_Protocols(self, packet_description):
        ck1, ck2, ck3, ck4 = False, False, False, False
        if 'TCP' in packet_description:
            ck1 = True
        elif 'UDP' in packet_description:
            ck2 = True
        elif 'ICMPv4' in packet_description:
            ck3 = True
        elif 'SCTP' in packet_description:
            ck4 = True
        return ck1 or ck2 or ck3 or ck4



    def Process_Packet(self, packet):
        ip_layer = scapy.layers.inet.IP if 'IP' in packet else scapy.layers.inet6.IPv6
        hex_stream = hexdump.dump(scapy.all.Raw(packet).load, sep=' ')

        # Remove Mac Adresses
        if 'Ether' in packet:
            hex_stream = hex_stream[42:]
        elif 'CookedLinux' in packet:
            hex_stream = hex_stream[48:]
        elif 'CookedLinuxV2' in packet:
            hex_stream = hex_stream[60:]


        # Remove IPs and Ports
        if ip_layer is scapy.layers.inet6.IPv6:
            #hex_stream = hex_stream[0:36] + hex_stream[132:]  # Use this for Keeping Src and Dst Ports
            hex_stream = hex_stream[0:36] + hex_stream[144:]
            hex_stream = [int(element, base=16) for element in hex_stream.split(" ")]
            return hex_stream
        else:
            if packet.getlayer(ip_layer).version == 4:
                #hex_stream = hex_stream[0:36] + hex_stream[60:] # Use this for Keeping Src and Dst Ports
                hex_stream = hex_stream[0:36] + hex_stream[72:]  # this removes src and dst ports
            elif packet.getlayer(ip_layer).version == 6:
                #hex_stream = hex_stream[0:36] + hex_stream[132:] # Use this for Keeping Src and Dst Ports
                hex_stream = hex_stream[0:36] + hex_stream[144:]  # This removes src and dst ports 
            hex_stream = [int(element, base=16) for element in hex_stream.split(" ")]
            return hex_stream



    def Pad_Sample(self, sample, target_sample_length):
        sample_length = len(sample)
        pad = target_sample_length - sample_length
        if pad == 0:
            return sample
        elif pad > 0:
            sample = sample + [0 for i in range(pad)]
        else:
            sample = sample[:target_sample_length]
        return sample



    def Get_Statitstical_Features(self, capture):
        if self.sample_type == 'unidirectional':
            fwd = self.Get_Unidirectional_Flow_List(capture)
        else:
            fwd, bwd = self.Get_Bidirectional_Flow_List(capture)
        # Return if no sessions of desired protocols are found
        if len(fwd) == 0: return []
        # Extract Unidirectional Features
        Dataframes, Fwd_Timestamps = [], []

        for fwd_flow in fwd:
            fwd_df = self.df_statistical.copy()
            fwd_df, fwd_timestamps = self.Extract_Fwd_Features(fwd_flow, fwd_df)
            Dataframes.append(fwd_df)
            Fwd_Timestamps.append(fwd_timestamps)
        if self.sample_type == 'unidirectional':
            return pd.concat(Dataframes, ignore_index=True)

        # Extract Bidirectional and Total Features
        for bwd_flow, df, fwd_timestamps in zip(bwd, Dataframes, Fwd_Timestamps):
            # Extract Bwd Features
            df, bwd_timestamps = self.Extract_Bwd_Features(bwd_flow, df)
            # Extract Total Features
            df = self.Calculate_Total_Size_Features(df)
            timestamps = fwd_timestamps + bwd_timestamps
            df = self.Calculate_Temporal_Features(timestamps, df, 'Flow ')
        return pd.concat(Dataframes, ignore_index=True)




    def Get_Unidirectional_Flow_List(self, capture):
        fwd = []
        for packet_description, packet_list in capture.items():
            if self.Check_For_Protocols(packet_description):
                fwd_flow = []
                for packet in packet_list:
                    fwd_flow.append(packet)
                fwd.append(fwd_flow)
        return fwd




    def Get_Bidirectional_Flow_List(self, capture):
        fwd, bwd = [], []
        for packet_description, packet_list in capture.items():
            if self.Check_For_Protocols(packet_description):
                # Get the srcIP of the first packet
                ip_layer = scapy.layers.inet.IP if 'IP' in packet_list[0] else scapy.layers.inet6.IPv6
                src_IP = packet_list[0][ip_layer].src
                fwd_flow, bwd_flow = [], []
                for packet in packet_list:
                    if packet[ip_layer].src == src_IP:
                        fwd_flow.append(packet)
                    else:
                        bwd_flow.append(packet)
                fwd.append(fwd_flow)
                bwd.append(bwd_flow)
        return fwd, bwd



    def Extract_Fwd_Features(self, fwd_flow, fwd_df):
        fwd_timestamps, fwd_total_bytes, fwd_payload_bytes = [], [], []
        for packet in fwd_flow:
            fwd_timestamps.append(float(packet.time))
            fwd_total_bytes.append(packet.__len__())
            fwd_payload_bytes.append(packet.payload.__len__())

        description = 'Fwd ' if self.sample_type == 'bidirectional' else 'Flow '
        # Calculate Size Features
        fwd_df = self.Calculate_Size_Features(len(fwd_flow), fwd_total_bytes, fwd_payload_bytes, fwd_df, description)

        # Calculate Temporal Features
        fwd_df = self.Calculate_Temporal_Features(fwd_timestamps, fwd_df, description)
        return fwd_df, fwd_timestamps



    def Calculate_Size_Features(self, packet_num, total_bytes, payload_bytes, df, description='Flow '):
        # These Feature have no problem if the flow contains only one packet
        df.loc[0, f'{description}Total Packets'] = packet_num
        df.loc[0, f'{description}Total Bytes'] = sum(total_bytes)

        df.loc[0, f'{description}Packet Bytes Min'] = min(total_bytes)
        df.loc[0, f'{description}Packet Bytes Max'] = max(total_bytes)
        df.loc[0, f'{description}Packet Bytes Avg'] = sum(total_bytes) / len(total_bytes)
        df.loc[0, f'{description}Packet Bytes Variance'] = np.var(total_bytes)

        df.loc[0, f'{description}Payload Bytes Min'] = min(payload_bytes)
        df.loc[0, f'{description}Payload Bytes Max'] = max(payload_bytes)
        df.loc[0, f'{description}Payload Bytes Avg'] = sum(payload_bytes) / len(payload_bytes)
        df.loc[0, f'{description}Payload Bytes Variance'] = np.std(payload_bytes)

        df.loc[0, f'{description}Header Bytes'] = np.sum(np.array(total_bytes) - np.array(payload_bytes))
        return df



    def Calculate_Temporal_Features(self, timestamps, df, description='Flow '):
        timestamps.sort()
        if (len(timestamps) == 1) or (timestamps[0] == 0 and len(timestamps) == 2):
            df = self.Handle_Temporal_Exceptions(df, description)
        else:
            pairwise_diff = np.diff(timestamps)
            if timestamps[0] == 0:
                df.loc[0, f'{description}Duration'] = timestamps[-1] - timestamps[1]
                pairwise_diff = pairwise_diff[1:]
            else:
                df.loc[0, f'{description}Duration'] = timestamps[-1] - timestamps[0]

            # Exception where timestamps are all the same for some reason (maybe the split)
            if df[f'{description}Duration'][0] == 0:
                df = self.Handle_Temporal_Exceptions(df, description)
                return df
            df.loc[0, f'{description}Bytes/s'] = df[f'{description}Total Bytes'][0] / df.loc[
                0, f'{description}Duration']
            df.loc[0, f'{description}Packets/s'] = len(timestamps) / (timestamps[-1] - timestamps[0])

            df.loc[0, f'{description}IAT Total'] = pairwise_diff.sum()
            df.loc[0, f'{description}IAT Min'] = pairwise_diff.min()
            df.loc[0, f'{description}IAT Max'] = pairwise_diff.max()
            df.loc[0, f'{description}IAT Avg'] = pairwise_diff.mean()
            df.loc[0, f'{description}IAT Variance'] = np.var(pairwise_diff)
        return df



    def Handle_Temporal_Exceptions(self, df, description):
        # Handles the cases where you have only one timestamp or zero timestamps (and assign 0 on the value)
        df.loc[0, f'{description}Duration'] = 0
        df.loc[0, f'{description}Bytes/s'] = 0

        df.loc[0, f'{description}Packets/s'] = 0
        df.loc[0, f'{description}IAT Total'] = 0
        df.loc[0, f'{description}IAT Min'] = 0
        df.loc[0, f'{description}IAT Max'] = 0
        df.loc[0, f'{description}IAT Avg'] = 0
        df.loc[0, f'{description}IAT Variance'] = 0
        return df



    def Extract_Bwd_Features(self, bwd_flow, df):
        if len(bwd_flow) == 0:
            bwd_timestamps, bwd_total_bytes, bwd_payload_bytes = [0], [0], [0]
        else:
            bwd_timestamps, bwd_total_bytes, bwd_payload_bytes = [], [], []
            for packet in bwd_flow:
                bwd_timestamps.append(float(packet.time))
                bwd_total_bytes.append(packet.__len__())
                bwd_payload_bytes.append(packet.payload.__len__())
        description = 'Bwd '
        # Calculate Size Features
        df = self.Calculate_Size_Features(len(bwd_flow), bwd_total_bytes, bwd_payload_bytes, df, description)

        # Calculate Temporal Features
        df = self.Calculate_Temporal_Features(bwd_timestamps, df, description)
        return df, bwd_timestamps



    def Calculate_Total_Size_Features(self, df):
        df.loc[0, 'Flow Total Packets'] = df['Fwd Total Packets'][0] + df['Bwd Total Packets'][0]
        df.loc[0, 'Flow Total Bytes'] = df['Fwd Total Bytes'][0] + df['Bwd Total Bytes'][0]

        df.loc[0, 'Flow Packet Bytes Min'] = min(df['Fwd Packet Bytes Min'][0], df['Bwd Packet Bytes Min'][0])
        df.loc[0, 'Flow Packet Bytes Max'] = min(df['Fwd Packet Bytes Max'][0], df['Bwd Packet Bytes Max'][0])
        df.loc[0, 'Flow Packet Bytes Avg'] = (df['Fwd Packet Bytes Avg'][0] + df['Bwd Packet Bytes Avg'][0]) / 2
        df.loc[0, f'Flow Packet Bytes Variance'] = ((df['Fwd Packet Bytes Variance'][0] * df['Fwd Total Packets'][0])
                                                    + (df['Bwd Packet Bytes Variance'][0] * df['Bwd Total Packets'][
                    0])) / (df['Fwd Total Packets'][0] + df['Bwd Total Packets'][0])

        df.loc[0, 'Flow Payload Bytes Min'] = min(df['Fwd Payload Bytes Min'][0], df['Bwd Payload Bytes Min'][0])
        df.loc[0, 'Flow Payload Bytes Max'] = max(df['Fwd Payload Bytes Max'][0], df['Bwd Payload Bytes Max'][0])
        df.loc[0, 'Flow Payload Bytes Avg'] = (df['Fwd Payload Bytes Avg'][0] + df['Bwd Payload Bytes Avg'][0]) / 2
        df.loc[0, 'Flow Payload Bytes Variance'] = ((df['Fwd Payload Bytes Variance'][0] * df['Fwd Total Packets'][0])
                                                    + (df['Bwd Payload Bytes Variance'][0] * df['Bwd Total Packets'][
                    0])) / (df['Fwd Total Packets'][0] + df['Bwd Total Packets'][0])

        df.loc[0, 'Flow Header Bytes'] = df['Fwd Header Bytes'][0] + df['Bwd Header Bytes'][0]
        return df