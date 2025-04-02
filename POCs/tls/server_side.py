from tls_utils import *
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from Certificate import Certificates


def pem_to_raw(pem_file_path):
    with open(pem_file_path, 'rb') as pem_file:
        # Read the PEM data
        pem_data = pem_file.read()
        # Load the PEM data using the cryptography library
        certi = x509.load_pem_x509_certificate(pem_data, default_backend())

        # Get the DER (binary) representation of the certificate
        raw_certificate = certi.public_bytes(encoding=serialization.Encoding.DER)
        return raw_certificate


def create_signature(private_key_path, message):
    with open(private_key_path, "rb") as key_file:
        key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,  # If your private key is encrypted, pass the password here
            backend=default_backend()
        )

    private_numbers = key.private_numbers()

    n = private_numbers.public_numbers.n
    d = private_numbers.d

    

    h = SHA256.new()
    h.update(message)
    h = h.digest()

    signature = nb_to_bytes(pow(bytes2int(h), d, n))

    return signature
    
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.backends import default_backend

def create_signature_with_params(private_key_path, client_random, server_random, public_key):
    # Load the private key
    with open(private_key_path, "rb") as key_file:
        key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,  # If your private key is encrypted, provide the password here
            backend=default_backend()
        )
    
    # Construct the message to be signed (ClientRandom + ServerRandom + other TLS parameters)
    message = client_random + server_random + bytes([0x03, 0x00, 0x17, 65]) + public_key

    # Hash the message using SHA-256
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    hashed_message = digest.finalize()

    # Sign the hashed message with RSA using PKCS#1 v1.5 padding
    signature = key.sign(
        hashed_message,
        padding=PKCS1v15(),
        algorithm=hashes.SHA256()
    )

    return signature 

    
def print_n_and_d(private_key_path):
    with open(private_key_path, "rb") as key_file:
        key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,  # If your private key is encrypted, pass the password here
            backend=default_backend()
        )

    private_numbers = key.private_numbers()

    n = private_numbers.public_numbers.n
    d = private_numbers.d

    print("N Value", n)
    print("D Value", d)


private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()
raw_public_key = public_key.public_bytes(encoding=serialization.Encoding.X962,
                                         format=serialization.PublicFormat.UncompressedPoint)

cert = pem_to_raw("example.com_cert.pem")

cert_len = len(cert)

server_random = bytes([0x71, 0xd8, 0x51, 0xb5, 0x3f, 0x78, 0x0b, 0x9d,
                       0x38, 0x08, 0xa3, 0xec, 0x22, 0x0d, 0xda, 0xaf,
                       0x26, 0x2a, 0xe8, 0xcc, 0xb0, 0xa0, 0x57, 0x1a,
                       0x39, 0x83, 0x1c, 0x52, 0xe7, 0xf9, 0x56, 0xbb])
server_hello = bytes([0x16, 0x03, 0x03, 0x00, 0x3d, 0x02, 0x00, 0x00,
                      0x39, 0x03, 0x03, 0x71, 0xd8, 0x51, 0xb5, 0x3f, 0x78, 0x0b, 0x9d,
                      0x38, 0x08, 0xa3, 0xec, 0x22, 0x0d, 0xda, 0xaf,
                      0x26, 0x2a, 0xe8, 0xcc, 0xb0, 0xa0, 0x57, 0x1a,
                      0x39, 0x83, 0x1c, 0x52, 0xe7, 0xf9, 0x56, 0xbb,
                      0x00, 0xc0, 0x2f, 0x00, 0x00, 0x11, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00,
                      0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00,
                      0x23, 0x00, 0x00])
certificate = bytes([0x16, 0x03, 0x03])
certificate += (cert_len + 10).to_bytes(2) + b'\x0b' + (cert_len + 6).to_bytes(3) + (cert_len + 3).to_bytes(
    3) + cert_len.to_bytes(3) + cert

server_key_exchange = bytes([0x16, 0x03, 0x03])

server_hello_done = bytes([0x16, 0x03, 0x03, 0x00, 0x04, 0x0e, 0x00, 0x00, 0x00]) + bytes([0x04, 0x01])

SERVER_IP, SERVER_PORT = "", 443


def main():
    global server_key_exchange

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((SERVER_IP, SERVER_PORT))
        sock.listen(5)

        client, addr = sock.accept()

        client_hello = client.recv(4096)
        print("recved client hello")
        client_random = client_hello[11:43]
        
        signature = create_signature("example.com_key.pem", client_random + server_random + bytes([0x03, 0x00, 0x17, 65]) + raw_public_key)
        
        server_key_exchange_content = len(signature).to_bytes(2) + signature
        server_key_exchange_content = bytes([0x03, 0x00, 0x17]) + len(raw_public_key).to_bytes(
            1) + raw_public_key + bytes([0x04, 0x01]) + server_key_exchange_content
        server_key_exchange_content = bytes([0x0c]) + len(server_key_exchange_content).to_bytes(
            3) + server_key_exchange_content

        server_key_exchange += len(server_key_exchange_content).to_bytes(2) + server_key_exchange_content

        client.sendall(server_hello)
        print("sent server hello")
        client.sendall(certificate)
        print("sent certificate")
        client.sendall(server_key_exchange)
        print("sent key exchange")
        client.sendall(server_hello_done)
        print("sent server hello done")
        client.recv(4096)
        print("recved clients message")


if __name__ == "__main__":
    main()
