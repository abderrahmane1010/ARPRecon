import socket
import struct
from arp_recon.core import ARPPacket
import netifaces as ni

def get_network_info(interface):
    try:
        interface_info = ni.ifaddresses(interface)
        mac_address = interface_info[ni.AF_LINK][0]['addr']
        ip_address = interface_info[ni.AF_INET][0]['addr']
        
        return mac_address, ip_address
    except KeyError as e:
        return "Information not available for this interface:", e
    except ValueError:
        return "Interface not found."

default_interface = ni.gateways()['default'][ni.AF_INET][1]


# # whois 129.88.43.75 (cousson.imag.fr)

def create_arp_request(src_mac, src_ip, dst_ip):
    target_mac = '00:00:00:00:00:00'
    target_ip = socket.inet_aton(dst_ip)

    eth_header = struct.pack("!6s6s2s", 
                             bytes.fromhex(target_mac.replace(':', '')), 
                             bytes.fromhex(src_mac.replace(':', '')), 
                             b'\x08\x06')  # Type ARP

    arp_header = struct.pack("!2s2s1s1s2s6s4s6s4s", 
                             b'\x00\x01',      # Type de matériel Ethernet
                             b'\x08\x00',      # Type de protocole IP
                             b'\x06',          # Longueur de l'adresse MAC
                             b'\x04',          # Longueur de l'adresse IP
                             b'\x00\x01',      # Opération (1 pour requête ARP)
                             bytes.fromhex(src_mac.replace(':', '')), 
                             socket.inet_aton(src_ip),
                             bytes.fromhex(target_mac.replace(':', '')), 
                             target_ip)

    packet = eth_header + arp_header
    return packet

def send_arp_request(packet, interface):
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    raw_socket.bind((interface, 0))
    raw_socket.send(packet)
    raw_socket.close()


my_mac, my_ip = get_network_info(default_interface)
dst_ip = "129.88.43.170"  

arp_request_packet = create_arp_request(my_mac, my_ip, dst_ip)
print(arp_request_packet)
arp_packet = ARPPacket(arp_request_packet,1)
arp_packet.unpack_arp()
print(arp_packet.who_has_form())
send_arp_request(arp_request_packet, default_interface)
