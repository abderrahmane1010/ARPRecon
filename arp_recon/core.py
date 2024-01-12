from .detector import detect_anomalies
from .analyzer import analyze_packets

def run():
    print("ARPRecon is running...")
    packets = analyze_packets()
    detect_anomalies(packets)
    print("Analysis complete.")
