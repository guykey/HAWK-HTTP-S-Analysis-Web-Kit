import socket
import ssl

with open("poisoning.html", "r", encoding="utf-8") as srcHtml:
    htmlContent = srcHtml.read()

htmlContent = htmlContent.encode()

# Create a TCP/IP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the localhost on port 4433 (or any port you choose)
server_socket.bind(('', 443))

# Listen for incoming connections
server_socket.listen(5)

# Wrap the socket with SSL
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain(certfile='example.com_cert.pem', keyfile='example.com_key.pem')


ssl_context.set_ecdh_curve('secp384r1')

print("Server is listening on https://localhost:443")

client_socket, address = server_socket.accept()
print(f"Connection from {address} accepted.")

# Wrap the client socket with SSL
secure_socket = ssl_context.wrap_socket(client_socket, server_side=True)

# Handle client communication
try:
    data = secure_socket.recv(1024)
    print(f"Received data: {data}")
    secure_socket.sendall(htmlContent)
finally:
    secure_socket.close()
