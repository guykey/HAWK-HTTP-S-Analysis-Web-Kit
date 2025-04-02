import socket
import protocol


def main():
    # Create a raw socket to capture network traffic using Npcap
    # AF_INET is for IPv4
    # SOCK_RAW for raw packets
    # IPPROTO_IP to capture all IP packets

    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

    # Replace 'YOUR_INTERFACE_IP' with the IP address of the interface you want to sniff
    try:
        conn.bind(("INVALID IP", 0))
    except Exception:
        print("Change the code in line 13 to your ip address")
        exit(1)

    # Include IP headers in captured packets
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Enable promiscuous mode
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    try:
        while True:
            # Capture a packet
            raw_data, addr = conn.recvfrom(65536)
            # Unpack the Ethernet frame (ignore it for IP layer packets)
            print_packet(raw_data)
            
    except KeyboardInterrupt:
        # Disable promiscuous mode
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        print("\nPacket sniffing stopped.")
                

def print_packet(raw_data):
    packet = protocol.Packet(raw_data)
    
    if not packet.tcp:
        return
        
    packet.print_packet()

    exit()
    

if __name__ == "__main__":
    main()
