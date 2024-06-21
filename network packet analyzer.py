from scapy.all import sniff, IP, TCP, UDP, Raw
import datetime

def packet_callback(packet):
    print("\n--- Packet Captured ---")
    print(f"Timestamp: {datetime.datetime.now()}")

    # Check for IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        
        # Check for TCP layer
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Protocol: TCP")
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
            # Check for payload
            if Raw in packet:
                print(f"Payload: {packet[Raw].load}")
        
        # Check for UDP layer
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Protocol: UDP")
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
            # Check for payload
            if Raw in packet:
                print(f"Payload: {packet[Raw].load}")

def start_sniffing(interface):
    print(f"Starting packet capture on interface: {interface}")
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    # Replace 'eth0' with your network interface
    interface = ''
    start_sniffing(interface)
