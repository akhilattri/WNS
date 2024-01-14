from Crypto.PublicKey import ECC

f = open('myprivatekey.pem','rt')
key = ECC.import_key(f.read())
f.close()

import socket

# address of the server
host = '192.168.1.4'

# same port
port = 7575

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

socket.connect((host, port))

socket.send("Hello my friend".encode('utf-8'))

print(socket.recv(1024).decode('utf-8'))