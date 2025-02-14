from scapy.all import sniff, IP, TCP

def packet_callback(packet):
    if packet.haslayer(IP):  # Check if the packet has an IP layer
        src_ip = packet[IP].src  # Get the source IP address
        dst_ip = packet[IP].dst  # Get the destination IP address
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")
        
        if packet.haslayer(TCP):  # Check if the packet has a TCP layer
            src_port = packet[TCP].sport  # Get the source port
            dst_port = packet[TCP].dport  # Get the destination port
            print(f"Source Port: {src_port}, Destination Port: {dst_port}")
        else:
            print("Non-TCP packet captured")
    else:
        print("Non-IP packet captured")

sniff(prn=packet_callback, count=2)  # Capture 10 packets