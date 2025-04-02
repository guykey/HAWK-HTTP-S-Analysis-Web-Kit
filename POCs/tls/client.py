import socket
from tls import TLS_handler
import tls_utils

URL = "guthib.com"

SERVER_IP, SERVER_PORT = URL, 443


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((SERVER_IP, SERVER_PORT))

        handler = TLS_handler(sock, SERVER_IP)
        handler.do_handshake()

        print(handler.send_http_get())
        #  handler.send(b"Hello server!")
        #print("Server: " + handler.recv(1024))
        
        #handler.send(b"hi there")
        print(handler.recv(1024))
        #print(handler.recv(1024))
        

if __name__ == "__main__":
    main()
