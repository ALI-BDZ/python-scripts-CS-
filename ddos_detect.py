import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP
import platform

# On Windows, we need ctypes to check for admin rights.
if platform.system().lower() == 'windows':
    import ctypes

THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")

def block_ip(ip):
    """
    Blocks the specified IP using the appropriate firewall command depending on the OS.
    """
    if platform.system().lower() == 'windows':
        # Windows: Use netsh to add a firewall rule.
        print(f"Blocking IP {ip} on Windows")
        os.system(f'netsh advfirewall firewall add rule name="Block IP {ip}" dir=in action=block remoteip={ip}')
    else:
        # Linux/Unix: Use iptables.
        print(f"Blocking IP {ip} on Linux/other OS")
        os.system(f'iptables -A INPUT -s {ip} -j DROP')

def packet_callback(packet):
    """
    This function is called for every captured packet.
    It counts packets per IP and, every second, calculates the packet rate.
    If an IP exceeds the threshold and is not already blocked, it calls block_ip().
    """
    # Extract the source IP address from the packet.
    src_ip = packet[IP].src
    packet_count[src_ip] += 1

    # Calculate the elapsed time since the last check.
    current_time = time.time()
    time_interval = current_time - start_time[0]

    # Once one second has passed, evaluate packet rates.
    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval
            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                block_ip(ip)
                blocked_ips.add(ip)

        # Clear the counts and reset the timer for the next interval.
        packet_count.clear()
        start_time[0] = current_time

if __name__ == "__main__":
    # Check for administrative privileges.
    if platform.system().lower() == 'windows':
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("This script requires admin privileges on Windows. Please run as Administrator.")
                sys.exit(1)
        except Exception as e:
            print("Admin check failed:", e)
            sys.exit(1)
    else:
        # For Linux/Unix systems, use geteuid() to ensure the script is running as root.
        if os.geteuid() != 0:
            print("This script requires root privileges.")
            sys.exit(1)

    # Initialize our data structures.
    packet_count = defaultdict(int)   # Dictionary to count packets per IP.
    start_time = [time.time()]          # List containing the start time (using a list for mutability).
    blocked_ips = set()                 # Set to keep track of already blocked IPs.

    print("Monitoring network traffic...")
    # Start sniffing IP packets and call packet_callback for each packet.
    sniff(filter="ip", prn=packet_callback)
