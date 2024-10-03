from scapy.all import sniff
import threading
import logging

class PacketSniffer:
    def __init__(self, circular_buffer, interfaces):
        self.circular_buffer = circular_buffer
        self.interfaces = interfaces

    def packet_handler(self, packet):
        #logging.info(f'Packet captured: {packet.summary()}')
        self.circular_buffer.add_packet(packet)

    def start_sniffing(self):
        sniff(
            prn=self.packet_handler,
            store=False,
            iface=self.interfaces,
            filter='tcp or udp or ip proto 132'
        )
    
    def start(self):
        sniff_thread = threading.Thread(target=self.start_sniffing)
        sniff_thread.daemon = True
        sniff_thread.start()
