# Server.py

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import socket

def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def perform_key_exchange(client_public_key, private_key):
    shared_key = private_key.exchange(ec.ECDH(), client_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'key derivation',
        backend=default_backend()
    ).derive(shared_key)
    return derived_key

def encrypt(message, key):
    cipher = Cipher(algorithms.AES(key), modes.CFB(b'\0' * 16), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(message) + encryptor.finalize()

def decrypt(ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.CFB(b'\0' * 16), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8888))
    server_socket.listen(1)

    print("Server listening on port 8888...")

    client_socket, address = server_socket.accept()
    print("Connection from", address)

    private_key, public_key = generate_key_pair()

    # Send the server's public key to the client
    client_socket.sendall(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    # Receive the client's public key
    client_public_key_bytes = client_socket.recv(1024)
    client_public_key = serialization.load_pem_public_key(client_public_key_bytes, default_backend())

    # Perform key exchange
    shared_key = perform_key_exchange(client_public_key, private_key)

    print("Shared Key:", shared_key.hex())

    # Example message to be encrypted
    message = b"Hello, client!"

    # Encrypt and send the message
    ciphertext = encrypt(message, shared_key)
    client_socket.sendall(ciphertext)

    # Receive and decrypt the message from the client
    received_ciphertext = client_socket.recv(1024)
    decrypted_message = decrypt(received_ciphertext, shared_key)
    print("Received Message:", decrypted_message.decode())

    client_socket.close()
    server_socket.close()

if __name__ == "__main__":
    start_server()
