
import socket 
from .utils import *
class Analyzer :
    
    alive_ips = []
    
    def __init__(self, arp_packet, aliveness):
        self.arp_packet = arp_packet
        if aliveness :
            self.aliveness_analysis()
    
    def aliveness_analysis(self):
        # Show 
        print(self.alive_ips)
        print([gethostnamebyaddr_or_getaddr(ip) for ip in self.alive_ips])
        print(len(self.alive_ips))
        if self.arp_packet.get_from_protocol() not in self.alive_ips :
            self.alive_ips.append(self.arp_packet.get_from_protocol())
        if self.arp_packet.get_to_protocol() not in self.alive_ips :
            self.alive_ips.append(self.arp_packet.get_to_protocol())
        pass

# def analyze_packets():
#     # Simuler la récupération et l'analyse des paquets ARP
#     packets = ["packet1", "packet2", "packet3"]  # Exemple de paquets
#     return packets
