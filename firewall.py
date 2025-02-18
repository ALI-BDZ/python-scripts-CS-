import os
import sys
import time
import platform
import ctypes  # Will be used on Windows
from collections import defaultdict
from scapy.all import sniff, IP, TCP

THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")

# Read IPs from a file and return a set of IP addresses.
def read_ip_file(filename):
    with open(filename, "r") as file:
        ips = [line.strip() for line in file]
    return set(ips)

# Check for Nimda worm signature.
def is_nimda_worm(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        payload = packet[TCP].payload
        return "GET /scripts/root.exe" in str(payload)
    return False

# Log events to a file with a timestamped filename.
def log_event(message):
    log_folder = "logs"
    os.makedirs(log_folder, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
    log_file = os.path.join(log_folder, f"log_{timestamp}.txt")
    
    with open(log_file, "a") as file:
        file.write(f"{message}\n")

# Unified function to block an IP address depending on the OS.
def block_ip(ip):
    if platform.system().lower() == "windows":
        print(f"Blocking IP {ip} on Windows")
        os.system(f'netsh advfirewall firewall add rule name="Block IP {ip}" dir=in action=block remoteip={ip}')
    else:
        print(f"Blocking IP {ip} on Linux/Unix")
        os.system(f"iptables -A INPUT -s {ip} -j DROP")

# Callback function that is called for every captured packet.
def packet_callback(packet):
    # Ensure the packet has an IP layer.
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src

    # Check if the source IP is in the whitelist.
    if src_ip in whitelist_ips:
        return

    # Check if the source IP is in the blacklist.
    if src_ip in blacklist_ips:
        block_ip(src_ip)
        log_event(f"Blocking blacklisted IP: {src_ip}")
        return

    # Check for the Nimda worm signature.
    if is_nimda_worm(packet):
        print(f"Blocking Nimda source IP: {src_ip}")
        block_ip(src_ip)
        log_event(f"Blocking Nimda source IP: {src_ip}")
        return

    # Count packets per IP.
    packet_count[src_ip] += 1

    current_time = time.time()
    time_interval = current_time - start_time[0]

    # Every 1 second, check the rate of packets per IP.
    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval
            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                block_ip(ip)
                log_event(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                blocked_ips.add(ip)
        packet_count.clear()
        start_time[0] = current_time

if __name__ == "__main__":
    # Check for administrative privileges in a cross-platform manner.
    if platform.system().lower() == "windows":
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("This script requires admin privileges on Windows. Please run as Administrator.")
                sys.exit(1)
        except Exception as e:
            print("Admin check failed:", e)
            sys.exit(1)
    else:
        if os.geteuid() != 0:
            print("This script requires root privileges.")
            sys.exit(1)

    # Load whitelist and blacklist IPs.
    whitelist_ips = read_ip_file("whitelist.txt")
    blacklist_ips = read_ip_file("blacklist.txt")

    # Initialize data structures.
    packet_count = defaultdict(int)  # Counts packets per source IP.
    start_time = [time.time()]         # Start time of the current interval (list for mutability).
    blocked_ips = set()                # Set of already blocked IPs.

    print("Monitoring network traffic...")
    # Start capturing IP packets; each packet is processed by packet_callback.
    sniff(filter="ip", prn=packet_callback)
