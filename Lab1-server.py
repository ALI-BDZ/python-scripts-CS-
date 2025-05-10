import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('localhost', 2025))
s.listen(1)

conn, addr = s.accept()
while True:
    data = conn.recv(1024).decode().strip()
    if data == 'exit':
        break
    conn.sendall(f"{len(data)}\n".encode())
conn.close()
s.close()