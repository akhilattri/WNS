from Crypto.PublicKey import ECC

key = ECC.generate(curve='P-256')

f = open('myprivatekey.pem','wt')
f.write(key.export_key(format='PEM'))
f.close()

import socket

# host = 'localhost'
# host = '127.0.0.1'
host = socket.gethostbyname(socket.gethostname())   #local ip address
# alternate way - run ipconfig in shell to get ipv4 address
# host = '192.168.1.4'

port = 7575

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.bind((host, port))

server.listen(5)    # optional parameter : to specify max devices waiting to connect at a time, after that reject new connections

while True:
    communication_socket, address = server.accept()
    print(f"Connected to {address}")
    message = communication_socket.recv(1024).decode('utf-8')  # convert from bytesteam to string
    print(f"Client's Message : {message}")
    communication_socket.send(f"Recieved your message!".encode('utf-8'))
    communication_socket.close()
    print(f"Connected Ended with {address}")