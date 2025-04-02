import socket
import requests
from packet_editor import PacketEditor

LISTEN_PORT = 8581


class PureHttpProxyServer:
    def __init__(self, host='localhost', port=LISTEN_PORT):
        self.server_address = (host, port)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(self.server_address)
        self.server_socket.listen(5)
        print(f"Proxy server listening on {host}:{port}")

    def start(self):
        try:
            while True:
                client_socket, client_address = self.server_socket.accept()
                print(f"Connection from {client_address}")
                self.handle_client(client_socket)
        except KeyboardInterrupt:
            print("Shutting down proxy server")
            self.server_socket.close()

    def handle_client(self, client_socket):
        # Receive the client's request
        request_data = self._receive_data(client_socket)
        if request_data is None:
            client_socket.close()
            return
        request_data = request_data.decode()
        lines = request_data.split('\n')
        request_line = lines[0]
        method, url, _ = request_line.split()
        url = url.replace('http://', '')
        if url.find('/') != -1:
            url = url[:url.find('/')]
        if url.endswith(':80'):
            url = url[:-4]
        if url.endswith(':443'):
            return
        if method == "CONNECT":
            return

        print("*"*30)
        print("Client:")
        print(request_data)

        # currently request data contains the original request of the client
        if input("Enter e for editing this packet: ").lower() == "e":
            pe = PacketEditor(text=request_data)
            request_data = pe.get_text()
            print("Updated packet:")
            print(request_data)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((url, 80))
        
        #request_data = input("Enter new request: ")
        sock.sendall(request_data.encode())
        
        response = self._receive_data(sock)
        print("Server:")
        print(response)
        print("*"*30)

        self._send_response(response, client_socket)
        client_socket.close()

    def _receive_data(self, client_socket):
        data = b''
        while True:
            part = client_socket.recv(4096)
            data += part
            if len(part) < 4096:
                break
        return data

    def _send_response(self, response, client_socket):
        client_socket.sendall(response)



def main():
    proxy_server = PureHttpProxyServer(host='localhost', port=8581)
    proxy_server.start()


if __name__ == "__main__":
    main()
