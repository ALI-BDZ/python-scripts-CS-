import socket

target = input("Enter IP/host to scan: ")

print(f"\nScanning {target} (ports 2020-2030)...")

for port in range(2020, 2031):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)  # Adjust timeout as needed
    try:
        s.connect((target, port))
        s.close()
        print(f"Port {port} is open")
    except:
        pass

print("\nScan complete")