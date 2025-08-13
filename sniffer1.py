from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        proto = "OTHER"
        ports = ""

        # Detect protocol and extract ports if applicable
        if TCP in packet:
            proto = "TCP"
            ports = f"{packet[TCP].sport} → {packet[TCP].dport}"
        elif UDP in packet:
            proto = "UDP"
            ports = f"{packet[UDP].sport} → {packet[UDP].dport}"
        elif ICMP in packet:
            proto = "ICMP"

        # Display info
        print(f"Time: {datetime.now().strftime('%H:%M:%S')}")
        print(f"Protocol: {proto}")
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        if ports:
            print(f"Ports: {ports}")
        print(f"Packet Size: {len(packet)} bytes")

        # Optional: Print payload (in ASCII, if printable)
        raw = bytes(packet.payload)
        try:
            ascii_payload = raw.decode('utf-8', errors='ignore')
            print(f"Payload (ASCII): {ascii_payload[:100]}")  # Limit output
        except:
            pass

        print("-" * 60)

print("Sniffing packets... Press Ctrl+C to stop.")
sniff(filter="ip", prn=process_packet, store=False)
