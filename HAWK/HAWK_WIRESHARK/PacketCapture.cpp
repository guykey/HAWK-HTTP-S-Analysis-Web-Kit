#include "PacketCapture.h"



double PacketCapture::mbCaptured = 0;

PacketCapture::PacketCapture()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    _handle = nullptr;
    _deviceToMonitor = nullptr;
    int choice = 0, i = 0;
    // Get the list of available devices
    if (pcap_findalldevs(&_allDevices, errbuf) == -1) {
        return;
    }
    NetworkDevice* curr = nullptr;
    for (curr = _allDevices; curr != nullptr; curr = curr->next) 
    {
        std::string deviceName(curr->name);
        size_t start = deviceName.find("{");
        size_t end = deviceName.find("}");
        if (start != std::string::npos && end != std::string::npos)
        {
            std::string guid = deviceName.substr(start, end - start + 1);
            std::string friendlyName = PacketCapture::turnGuidToCommonName(guid);
            if (friendlyName != "(Unknown)")
            {
                this->_deviceNames.push_back(friendlyName);
                //add friendly name to guid
                this->_deviceNameToGuid[friendlyName] = deviceName;
            }
        }
    }

}

const std::vector<std::string>& PacketCapture::getAllDeviceNames()
{
    return this->_deviceNames;
}

void PacketCapture::listenDevice(const std::string& deviceFriendlyName)
{
    static char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    //if there was a previous handle, close it
    if (_handle)
    {
        if (_listening)
        {
            _listening = false;
            pcap_breakloop(_handle);
        }
        pcap_close(_handle);
    }

    this->_pendingToView.reopen();

    if (this->_deviceNameToGuid.count(deviceFriendlyName) <= 0)
        return;

    std::string deviceGuid = this->_deviceNameToGuid[deviceFriendlyName];

    _deviceToMonitorName = deviceGuid;

    
    this->_handle = pcap_open_live(deviceGuid.c_str(), 65536, 1, 1000, errbuf);
    if (!this->_handle) {
        std::cerr << "Unable to open the device: " << errbuf << "\n";
        return;
    }
    _listening = true;
    pcap_loop(_handle, 0, addPending, (u_char*)this);
}

void PacketCapture::halt()
{
    this->_pendingToView.close();
    if (_handle)
    {
        if (_listening)
        {
            _listening = false;
            pcap_breakloop(_handle);
        }
        pcap_close(_handle);
    }

    this->_handle = nullptr;
}

Packet* PacketCapture::getPacket()
{
    Packet* p = this->_pendingToView.pop();
    return p;
}

void PacketCapture::pushPacket(Packet* p)
{
    this->_pendingToView.push(p);
}


PacketCapture::~PacketCapture()
{
    this->halt();

    if(_allDevices)
        pcap_freealldevs(_allDevices);

}

double PacketCapture::mbsCaptured()
{
    return PacketCapture::mbCaptured;
}


void PacketCapture::listen() 
{
    // Start capturing packets
    pcap_loop(_handle, 0, printConsole, nullptr);

}




void PacketCapture::addPending(unsigned char* param, const PacketInfo* header, const unsigned char* pkt_data)
{
    Packet* newPacket = new PcapPacket((byte*)pkt_data, (size_t)(header->len));
    
    mbCaptured += header->len * 0.000001;//byte to mb
    PacketCapture* _this = (PacketCapture*)param;

    _this->pushPacket(newPacket);

}

std::string PacketCapture::turnGuidToCommonName(const std::string& guid)
{
    static std::string commonName = "(Unknown)";
    commonName = "(Unknown)";
    //use the registry, the data is there
    //the guid {4D36E972... is the common guid parent for net devices
    //and under that we should have the devices data
    const std::string regPath = "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\" + guid + "\\Connection";

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char nameBuffer[256];
        DWORD bufferSize = sizeof(nameBuffer);

        if (RegQueryValueExA(hKey, "Name", NULL, NULL, (LPBYTE)nameBuffer, &bufferSize) == ERROR_SUCCESS) {
            commonName = nameBuffer;
        }

        RegCloseKey(hKey);
    }

    return commonName;
}


//for debugging!


void PacketCapture::printConsole(unsigned char* param, const PacketInfo* header, const unsigned char* pkt_data) {
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

PacketCapture::PacketCapture(NetworkDevice* device)
{
    char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
    _allDevices = nullptr;

    this->_deviceToMonitor = device;
    // Open the device for packet capture
    this->_handle = pcap_open_live(_deviceToMonitor->name, 65536, 1, 1000, errbuf);
    if (!this->_handle) {
        std::cerr << "Unable to open the device: " << errbuf << "\n";
        return;
    }
}

PacketCapture::PacketCapture(bool debug)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    _handle = nullptr;
    _deviceToMonitor = nullptr;
    int choice = 0, i = 0;

    // Get the list of available devices
    if (pcap_findalldevs(&_allDevices, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << "\n";
        return;
    }
    NetworkDevice* curr = nullptr;
    for (curr = _allDevices; curr != nullptr; curr = curr->next) {

        std::string deviceName(curr->name);

        size_t start = deviceName.find("{");
        size_t end = deviceName.find("}");
        if (start != std::string::npos && end != std::string::npos)
        {
            std::string guid = deviceName.substr(start, end - start + 1);
            std::string friendlyName = PacketCapture::turnGuidToCommonName(guid);

            std::cout << ++i << ". " << friendlyName << "  (" << (curr->description ? curr->description : "No description")
                << ")" << std::endl;
            continue;
        }

        std::cout << ++i << ". " << (curr->description ? curr->description : "(No description)")
            << " [" << deviceName << "]\n";
    }
    if (i == 0) {
        std::cout << "No devices found.\n";
        return;
    }

    std::cout << "\nEnter the device number to capture from: ";
    std::cin >> choice;
    if (choice < 1 || choice > i) {
        std::cerr << "Invalid choice.\n";
        return;
    }
    //move through the linked list
    for (curr = _allDevices, i = 1; curr && i < choice; curr = curr->next, i++);
    if (!curr) {
        std::cerr << "Device selection failed.\n";
        return;
    }
    this->_deviceToMonitor = curr;

    _handle = pcap_open_live(curr->name, 65536, 1, 1000, errbuf);
    if (!_handle) {
        std::cerr << "Unable to open the device: " << errbuf << "\n";
        return;
    }
}

