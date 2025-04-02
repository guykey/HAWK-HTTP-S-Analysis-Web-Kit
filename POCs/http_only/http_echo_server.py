import socket

def handle_request(client_connection):
    # Read the request data
    request_data = client_connection.recv(1024).decode()
    
    # Print the received request (optional, for debugging)
    print("Received request:")
    print(request_data)

    # Send the response to the client
    client_connection.sendall(request_data.encode())  # sends back what it got

    # Close the connection
    client_connection.close()

def run_server(host='localhost', port=80):
    # Create a socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Bind the socket to the host and port
    server_socket.bind((host, port))
    
    # Listen for incoming connections
    server_socket.listen(1)
    print(f"Listening on {host}:{port}...")

    while True:
        # Accept a new connection
        client_connection, client_address = server_socket.accept()
        print(f"Accepted connection from {client_address}")
        
        # Handle the request
        handle_request(client_connection)

if __name__ == '__main__':
    run_server()
