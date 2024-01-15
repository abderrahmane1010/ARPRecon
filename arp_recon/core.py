from .utils import *
from .arp_packet import *
from .detector import *
from .capture import *
from .analyzer import *
import socket
import argparse

def parse_args():
    # parser = argparse.ArgumentParser(description='ARP Packet Analysis Tool')
    # subparsers = parser.add_subparsers(dest='mode', help='Choose the mode: detection, capture, or analyze')

    # # Detection mode
    # detection_parser = subparsers.add_parser('detection', help='ARP packet detection mode')
    # detection_parser.add_argument('--detect-arp-poison', action='store_true', help='Detect ARP poisoning')

    # # Capture mode
    # capture_parser = subparsers.add_parser('capture', help='Packet capture mode')
    # capture_parser.add_argument('--capture-packets', action='store_true', help='Capture packets')

    # # Analyze mode
    # analyze_parser = subparsers.add_parser('analyze', help='Packet analysis mode')
    # analyze_parser.add_argument('--analyze-packets', action='store_true', help='Analyze captured packets')


    parser = argparse.ArgumentParser(description='ARP Packet Analysis Tool')
    parser.add_argument('--detect', type=str, help='Detect ARP poisoning')
    parser.add_argument('--capture', type=str, help='Capture packets')
    parser.add_argument('--analyze', type=str, help='Analyze captured packets')

    return parser.parse_args()


    
def run():
    args = parse_args()
    
    banner(args)
    
    # Name of the active interface
    print(f'Capturing on {colorize(name_of_active_interface(),"info")}')
    
    # Capture the packets 
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    id = 1
    try:
        while True:
            packet, addr = s.recvfrom(65535)
            if is_arp(packet) :
                # ARP packet :
                arp_packet = ARPPacket(packet,id)
                arp_packet.unpack_arp()
                print(arp_packet.who_has_form())
                
                if args.detect :
                    # Detector :
                    detector = Detector(arp_packet)
                    detector.detect_arp_poisonning()

                if args.capture :
                    # Capture :
                    capture = Capture(arp_packet, "captures", "cap1.csv")

                if args.analyze :
                    Analyzer(arp_packet, aliveness=True)
    
                id+=1
    except KeyboardInterrupt:
            print("Stop Intercepting")
            s.close()

    
