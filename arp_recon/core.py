from .detector import detect_anomalies
from .analyzer import analyze_packets
from .utils import *
from .arp_packet import *
from .detector import *
import socket
    
def run():
    banner()
    
    # Name of the active interface
    print(f'Capturing on {colorize(name_of_active_interface(),"info")}')
    
    # Capture the packets 
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    id = 1
    try:
        while True:
            packet, addr = s.recvfrom(65535)
            if is_arp(packet) :
                arp_packet = ARPPacket(packet,id)
                arp_packet.unpack_arp()
                detector = Detector(arp_packet)
                detector.detect_arp_poisonning()
                print(arp_packet.who_has_form())
                id+=1
    except KeyboardInterrupt:
            print("Stop Intercepting")
            s.close()

    
    packets = analyze_packets()
    detect_anomalies(packets)
    print("Analysis complete.")
