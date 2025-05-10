import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('localhost', 2025))

while True:
    msg = input("> ")
    s.sendall((msg + "\n").encode())
    if msg == 'exit':
        break
    print(s.recv(1024).decode().strip())
   



s.close()