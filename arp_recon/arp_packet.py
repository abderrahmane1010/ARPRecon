from struct import *
from resources import ethertypes as protocols
import socket
from .utils import colorize as colorize
import netifaces

class ARPPacket:
    
    ip_mac_mapping = {}
    ARP_POISONING_DETECTION = False
    """Classe pour analyser les paquets ARP."""
    def __init__(self, packet, id):
        self.packet = packet
        self.packet_header = packet[14:42]
        self.hard_type = ""
        self.protocol_type = ""
        self.length_hard = ""
        self.length_protocol = ""
        self.operation = ""
        self.from_hard = ""
        self.from_protocol = ""
        self.to_hard = ""
        self.to_protocol = ""
        self.id = id

    def unpack_arp(self):
        """Décompose le paquet ARP et extrait les informations."""
        arp = unpack('!HHBBH6s4s6s4s', self.packet_header)
        hard_type, protocol_type, length_hard, length_protocol, operation = arp[:5]
        hard_address_source = ARPPacket._to_mac(arp[5])
        protocol_address_source = socket.inet_ntoa(arp[6])
        hard_address_dest = ARPPacket._to_mac(arp[7])
        to = "Broadcast" if hard_address_dest == '00:00:00:00:00:00' else hard_address_dest
        protocol_address_dest = socket.inet_ntoa(arp[8])
        
        self.hard_type = protocols.etherType.get(self._to_hex(self.packet[14:16]), self._to_hex(self.packet[14:16]))
        self.protocol_type = protocols.etherType.get(self._to_hex(self.packet[16:18]), self._to_hex(self.packet[16:18]))
        self.length_hard = length_hard
        self.length_protocol = length_protocol
        self.operation = operation
        self.from_hard = hard_address_source
        self.from_protocol = protocol_address_source
        self.to_hard = to
        self.to_protocol = protocol_address_dest
        
        if self.ARP_POISONING_DETECTION == True : # ACTIVATE ARP POISONING DETECTION
            self.arp_poisoning_detection()
        
        return hard_type, protocol_type, length_hard, length_protocol, operation, hard_address_source, protocol_address_source, to, protocol_address_dest
    
    def arp_poisoning_detection(self):
        print(self.ip_mac_mapping)
        if self.from_protocol in self.ip_mac_mapping :
            if self.ip_mac_mapping[self.from_protocol] != self.from_hard :
                print(colorize(f'Potential ARP poisoning attack detected: {self.from_protocol} has two MAC addresses [{self.ip_mac_mapping[self.from_protocol]} and {self.from_hard}]',"error"))
            else :
                pass
        else :
            self.ip_mac_mapping[self.from_protocol] = self.from_hard
    
    @staticmethod
    def arp_type(number):
        """Retourne le type de paquet ARP."""
        return "Request" if number == 1 else "Replay" if number == 2 else "Unknown"
        
        
    @staticmethod
    def _to_hex(data):
        """Convertit les données en chaîne hexadécimale."""
        return ''.join(f'{byte:02x}' for byte in data)
    
    @staticmethod
    def _to_mac(data):
        """Convertit les données en chaîne hexadécimale."""
        return ':'.join(f'{byte:02x}' for byte in data)

    def is_gateway(self, ip_address):
        for gateway, interface, true_false in netifaces.gateways()[netifaces.AF_INET]:
            if ip_address == gateway :
                return True
        return False


    def address_to_gateway(self, ip_address):
        interface_gateway = ""
        for gateway, interface, true_false in netifaces.gateways()[netifaces.AF_INET]:
            if ip_address == gateway :
                interface_gateway = interface
        if self.is_gateway(ip_address) :
            return f'Gateway [{interface_gateway[0:8]}]'
        else :
            try:
                hostname, _, _ = socket.gethostbyaddr(ip_address)
                return hostname
            except socket.herror as e:
                return ip_address
            
    
    def who_has_form(self):
        phrase = f'{self.id} '
        if self.operation == 1 :
            phrase+= f'{colorize("[Request]","magenta")} Who has {colorize(self.address_to_gateway(self.to_protocol), "info")} ? Tell {colorize(self.address_to_gateway(self.from_protocol),"ok")}'
        elif self.operation == 2:
            phrase+=  f'{colorize("[Replay]","cyan")} {colorize(self.address_to_gateway(self.from_protocol), "ok")} is at {colorize(self.from_hard, "warning")}'
        else :
            phrase+=  f''
        return phrase
        
    def __str__(self):
        return f'{self.hard_type} | {self.protocol_type} | {self.length_hard} | {self.length_protocol} | {ARPPacket.arp_type(self.operation)} | {self.from_hard} | {self.from_protocol} | {self.to_hard} | {self.to_protocol}'

