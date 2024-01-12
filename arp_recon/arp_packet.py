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
        self._hard_type = ""
        self._protocol_type = ""
        self._length_hard = ""
        self._length_protocol = ""
        self._operation = ""
        self._from_hard = ""
        self._from_protocol = ""
        self._to_hard = ""
        self._to_protocol = ""
        self.id = id

    def get_hard_type(self):
        return self._hard_type
    def get_protocol_type(self):
        return self._protocol_type
    def get_length_hard(self):
        return self._length_hard
    def get_length_protocol(self):
        return self._length_protocol
    def get_operation(self):
        return self._operation
    def get_from_hard(self):
        return self._from_hard
    def get_from_protocol(self):
        return self._from_protocol
    def get_to_hard(self):
        return self._to_hard
    def get_to_protocol(self):
        return self._to_protocol
    
    def set_hard_type(self, value):
        self._hard_type = value
    def set_protocol_type(self, value):
        self._protocol_type = value
    def set_length_hard(self, value):
        self._length_hard = value
    def set_length_protocol(self, value):
        self._length_protocol = value
    def set_operation(self, value):
        self._operation = value
    def set_from_hard(self, value):
        self._from_hard = value
    def set_from_protocol(self, value):
        self._from_protocol = value
    def set_to_hard(self, value):
        self._to_hard = value
    def set_to_protocol(self, value):
        self._to_protocol = value
    
    def unpack_arp(self):
        """Décompose le paquet ARP et extrait les informations."""
        arp = unpack('!HHBBH6s4s6s4s', self.packet_header)
        hard_type, protocol_type, length_hard, length_protocol, operation = arp[:5]
        hard_address_source = ARPPacket._to_mac(arp[5])
        protocol_address_source = socket.inet_ntoa(arp[6])
        hard_address_dest = ARPPacket._to_mac(arp[7])
        to = "Broadcast" if hard_address_dest == '00:00:00:00:00:00' else hard_address_dest
        protocol_address_dest = socket.inet_ntoa(arp[8])
        
        self.set_hard_type(protocols.etherType.get(self._to_hex(self.packet[14:16]), self._to_hex(self.packet[14:16])))
        self.set_protocol_type(protocols.etherType.get(self._to_hex(self.packet[16:18]), self._to_hex(self.packet[16:18])))
        self.set_length_hard(length_hard)
        self.set_length_protocol(length_protocol)
        self.set_operation(operation)
        self.set_from_hard(hard_address_source)
        self.set_from_protocol(protocol_address_source)
        self.set_to_hard(to)
        self.set_to_protocol(protocol_address_dest)
        
        if self.ARP_POISONING_DETECTION == True : # ACTIVATE ARP POISONING DETECTION
            self.arp_poisoning_detection()
        
        return hard_type, protocol_type, length_hard, length_protocol, operation, hard_address_source, protocol_address_source, to, protocol_address_dest
    
    # def arp_poisoning_detection(self):
    #     print(self.ip_mac_mapping)
    #     if self.from_protocol in self.ip_mac_mapping :
    #         if self.ip_mac_mapping[self.from_protocol] != self.from_hard :
    #             print(colorize(f'Potential ARP poisoning attack detected: {self.from_protocol} has two MAC addresses [{self.ip_mac_mapping[self.from_protocol]} and {self.from_hard}]',"error"))
    #         else :
    #             pass
    #     else :
    #         self.ip_mac_mapping[self.from_protocol] = self.from_hard
    
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
        if self.get_operation() == 1 :
            phrase+= f'{colorize("[Request]","magenta")} Who has {colorize(self.address_to_gateway(self.get_to_protocol()), "info")} ? Tell {colorize(self.address_to_gateway(self.get_from_protocol()),"ok")}'
        elif self.get_operation() == 2:
            phrase+=  f'{colorize("[Replay]","cyan")} {colorize(self.address_to_gateway(self.get_from_protocol()), "ok")} is at {colorize(self.get_from_hard(), "warning")}'
        else :
            phrase+=  f''
        return phrase
        
    def __str__(self):
        return f'{self.get_hard_type()} | {self.get_protocol_type()} | {self.get_length_hard()} | {self.get_length_protocol()} | {ARPPacket.arp_type(self.get_operation)()} | {self.get_from_hard()} | {self.get_from_protocol()} | {self.get_to_hard()} | {self.get_to_protocol()}'

