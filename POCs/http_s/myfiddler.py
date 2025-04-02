import socket
import ssl
import threading
import select
import os
import generate_cert_for_domain

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend
import datetime

with open("ca_cert.pem", "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

with open("ca_key.pem", "rb") as f:
    ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

# Configuration
LISTEN_HOST = '127.0.0.1'
LISTEN_PORT = 8582
BUFFER_SIZE = 4096
CERT_FILE = 'cert.pem'
KEY_FILE = 'private.key'

output_file = "requests.txt"

output_file_descriptor = open(output_file, "wb")

file_lock = threading.Lock()

tunnel_addresses = ["static.", "google", "google.com", "gstatic.com", "googleapi", "microsoft"]


def is_tunnel_address(request):
    for addr in tunnel_addresses:
        if addr in request:
            return True
    return False


def handle_client(client_socket, client_address):
    # Receive the client's request
    request = client_socket.recv(BUFFER_SIZE).decode('utf-8')
    if request.startswith("CONNECT") and not is_tunnel_address(request):
        handle_connect(client_socket, client_address, request)
    elif request.startswith("CONNECT") and is_tunnel_address(request):
        tunnel_https(client_socket, client_address, request)
    else:
        handle_http(client_socket, client_address, request)


def handle_connect(client_socket, client_address, request):
    # Parse the CONNECT request to extract the target host and port
    target_host, target_port = request.split()[1].split(":")
    target_port = int(target_port)

    print(f"[*] Handling CONNECT request to {target_host}:{target_port}")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((target_host, target_port))
    context = ssl.create_default_context()
    server_socket = context.wrap_socket(server_socket, server_hostname=target_host)
    print("Connected to server")
    # Send HTTP 200 OK to the client to signal readiness for tunneling
    client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if not (os.path.exists(f"temp_certificates\\{target_host}_cert.pem") and os.path.exists(f"temp_certificates\\{target_host}_key.pem")):
        domain_cert, domain_key = generate_cert_for_domain.generate_domain_cert(target_host, ca_cert, ca_key)
        with open(f"temp_certificates\\{target_host}_cert.pem", "w", encoding="utf-8") as temp_cert:
            temp_cert.write(domain_cert.public_bytes(Encoding.PEM).decode())
        with open(f"temp_certificates\\{target_host}_key.pem", "w", encoding="utf-8") as temp_key:
            temp_key.write(domain_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL,
                                                     NoEncryption()).decode())

    context.load_cert_chain(certfile=f"temp_certificates\\{target_host}_cert.pem",
                            keyfile=f"temp_certificates\\{target_host}_key.pem")
    #context.check_hostname = False
    #context.do_handshake_on_connect = False

    client_socket = context.wrap_socket(client_socket,
                                        server_side=True)
    # Wrap the client socket with SSL to intercept the HTTPS traffic

    # Forward data between the client and the server
    forward_traffic(client_socket, server_socket)


def tunnel_https(client_socket, client_address, request):
    # Parse the CONNECT request to extract the target host and port
    target_host, target_port = request.split()[1].split(":")
    target_port = int(target_port)

    print(f"[*] Tunneling request to {target_host}:{target_port}")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((target_host, target_port))
    print("Connected to server")
    # Send HTTP 200 OK to the client to signal readiness for tunneling
    client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    # Wrap the client socket with SSL to intercept the HTTPS traffic

    # Forward data between the client and the server
    forward_traffic(client_socket, server_socket, False)


def handle_http(client_socket, client_address, request):
    # Parse the request to determine the target server
    try:
        host_line = next(line for line in request.splitlines() if line.startswith("Host:"))
        target_host = host_line.split()[1]
        target_port = 80  # Default port for HTTP
        if ":" in target_host:
            target_host, target_port = target_host.split(":")
            target_port = int(target_port)
    except Exception as e:
        print(f"[!] Error parsing HTTP request: {e}")
        client_socket.close()
        return

    print(f"[*] Handling HTTP request to {target_host}:{target_port} from {client_address}")

    # Create a socket to connect to the target server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((target_host, target_port))

    # Forward the client's request to the server
    server_socket.sendall(request.encode('utf-8'))

    # Forward data between the client and the server
    forward_traffic(client_socket, server_socket)


def forward_traffic(client_socket, server_socket, save_to_file=True):
    # This method forwards data between the client and the server in both directions
    sockets = [client_socket, server_socket]
    while True:
        # Wait until one of the sockets has data ready to be read
        readable, _, _ = select.select(sockets, [], [])
        if client_socket in readable:
            data = client_socket.recv(BUFFER_SIZE)
            if len(data) == 0:
                break  # Client closed the connection
            if save_to_file:
                with file_lock:
                    output_file_descriptor.write(b"Client:")
                    output_file_descriptor.write(data)
                    output_file_descriptor.write(b"\n")
            server_socket.sendall(data)
        if server_socket in readable:
            data = server_socket.recv(BUFFER_SIZE)
            if len(data) == 0:
                break  # Server closed the connection
            if save_to_file:
                with file_lock:
                    output_file_descriptor.write(b"Server:")
                    output_file_descriptor.write(data)
                    output_file_descriptor.write(b"\n")
            client_socket.sendall(data)

    # Close both sockets when done
    client_socket.close()
    server_socket.close()


def open_chrome():
    os.system("Chrome.exe --ignore-certificate-errors")


def start_proxy():
    # chrome_thread = threading.Thread(target=open_chrome)
    # chrome_thread.start()
    # Create a socket to listen for incoming connections
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.bind((LISTEN_HOST, LISTEN_PORT))
    proxy_socket.listen(5)
    print(f"[*] Listening on {LISTEN_HOST}:{LISTEN_PORT}...")

    while True:
        # Accept a client connection
        client_socket, client_address = proxy_socket.accept()
        # print(f"[*] Accepted connection from {client_address}")

        # Handle the client connection in a new thread        
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()


if __name__ == "__main__":
    start_proxy()
