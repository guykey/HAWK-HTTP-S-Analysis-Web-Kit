#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <cstring>

#include "PacketCapture.h"

void packetHandler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    std::cout << "\nPacket captured: " << header->len << " bytes\n";

    // Print packet data in hex and ASCII
    for (u_int i = 0; i < header->len; i++) {
        if (i % 16 == 0) std::cout << "\n"; // New line every 16 bytes

        std::cout << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<int>(pkt_data[i]) << " ";

        if (i % 16 == 15 || i == header->len - 1) { // Print ASCII
            std::cout << "  ";
            for (u_int j = i / 16 * 16; j <= i; j++) {
                if (std::isprint(pkt_data[j]))
                    std::cout << static_cast<char>(pkt_data[j]);
                else
                    std::cout << '.';
            }
        }
    }
    std::cout << "\n";
}
/*
int main() {
    pcap_if_t* alldevs, * device;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Get the list of available devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << "\n";
        return 1;
    }

    int i = 0;
    for (device = alldevs; device != nullptr; device = device->next) {
        std::cout << ++i << ". " << (device->description ? device->description : "(No description)")
            << " [" << device->name << "]\n";
    }

    if (i == 0) {
        std::cout << "No devices found.\n";
        return 1;
    }

    int choice;
    std::cout << "\nEnter the device number to capture from: ";
    std::cin >> choice;

    if (choice < 1 || choice > i) {
        std::cerr << "Invalid choice.\n";
        return 1;
    }

    // Select the chosen device
    for (device = alldevs, i = 1; device && i < choice; device = device->next, i++)
        ;

    if (!device) {
        std::cerr << "Device selection failed.\n";
        return 1;
    }

    // Open the device for packet capture
    pcap_t* handle = pcap_open_live(device->name, 65536, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Unable to open the device: " << errbuf << "\n";
        return 1;
    }

    std::cout << "Listening on device: " << (device->description ? device->description : device->name) << "\n";

    // Start capturing packets
    pcap_loop(handle, 0, packetHandler, nullptr);

    // Clean up
    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}
*/

int main()
{
    PacketCapture c;

    c.listen();
}

