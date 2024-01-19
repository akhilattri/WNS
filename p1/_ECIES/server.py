from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import socket
import os

def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def perform_key_exchange(local_private_key, remote_public_key):
    shared_key = local_private_key.exchange(ec.ECDH(), remote_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'key derivation',
        backend=default_backend()
    ).derive(shared_key)
    return derived_key

def encrypt(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return iv + ciphertext

def decrypt(ciphertext, key):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8888))
    server_socket.listen(1)

    print("Server listening on port 8888...")

    client_socket, address = server_socket.accept()
    print("Connection from", address)

    # Generate key pair for server
    server_private_key, server_public_key = generate_key_pair()

    # Send server's public key to the client
    client_socket.sendall(server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    # Receive client's public key
    client_public_key_bytes = client_socket.recv(1024)
    client_public_key = serialization.load_pem_public_key(client_public_key_bytes, default_backend())

    # Perform key exchange
    shared_key_server = perform_key_exchange(server_private_key, client_public_key)

    # Example message to be encrypted
    message_from_server = b"Hello, client! This is a secure message from the server."

    # Encrypt and send the message
    encrypted_message = encrypt(message_from_server, shared_key_server)
    client_socket.sendall(encrypted_message)

    # Receive and decrypt the message from the client
    received_ciphertext = client_socket.recv(1024)
    decrypted_message = decrypt(received_ciphertext, shared_key_server)
    print("Received Message from Client:", decrypted_message.decode())

    client_socket.close()
    server_socket.close()

if __name__ == "__main__":
    start_server()
