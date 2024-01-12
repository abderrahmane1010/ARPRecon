from .utils import *

class Detector :
    
    ip_mac_mapping = {}
    show_ip_mac_associations = True # To show or not the ip_mac associations
    
    def __init__(self, arp_packet):
        self.arp_packet = arp_packet
    
    def detect_arp_poisonning(self):
        if self.show_ip_mac_associations :
            print(self.ip_mac_mapping)
        if self.arp_packet.get_from_protocol() in self.ip_mac_mapping :
            if self.ip_mac_mapping[self.arp_packet.get_from_protocol()] != self.arp_packet.get_from_hard() :
                print(colorize(f'Potential ARP poisoning attack detected: {self.arp_packet.get_from_protocol()} has two MAC addresses [{self.ip_mac_mapping[self.arp_packet.get_from_protocol()]} and {self.arp_packet.get_from_hard()}]',"error"))
            else :
                pass
        else :
            self.ip_mac_mapping[self.arp_packet.get_from_protocol()] = self.arp_packet.get_from_hard()
    
    
def detect_anomalies(packets):
    suspicious_packets = []
    for packet in packets:
        if is_packet_suspicious(packet):
            print(f"Suspicious packet detected: {packet}")
            suspicious_packets.append(packet)
    return suspicious_packets