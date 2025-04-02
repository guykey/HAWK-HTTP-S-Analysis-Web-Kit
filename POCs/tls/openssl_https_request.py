import ssl
import socket

hostname = '127.0.0.1'
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)

# Specify the cipher suite you want to use
context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')  # Example cipher suite

# Create a socket and wrap it with the SSL context
sock = socket.create_connection((hostname, 443))
ssl_sock = context.wrap_socket(sock, server_hostname=hostname)

# Initiate the handshake (which sends the ClientHello)
ssl_sock.do_handshake()


ssl_sock.send(b"GET / HTTP/1.1\r\nHost: kfc.com\r\n\r\n")

l = ssl_sock.recv(4096).decode()
print(l)
print('TLS handshake complete')
ssl_sock.close()
