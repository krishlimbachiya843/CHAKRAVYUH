import socket
s = socket.socket()
s.connect(('127.0.0.1', 2121))
print("Banner:", s.recv(1024).decode().strip())
s.sendall(b'USER admin\r\n'); print(s.recv(1024).decode().strip())
s.sendall(b'PASS admin123\r\n'); print(s.recv(1024).decode().strip())
s.sendall(b'QUIT\r\n')
s.close()
print("FTP attack sent!")