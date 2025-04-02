#include "WinDivertDev.h"


#include "ProxyServer.hpp"


WinDivertDev::WinDivertDev(unsigned short port, WINDIVERT_LAYER listenLayer)
{

    this->_listenLayer = listenLayer;
    
    _port = port;
    _handle = NULL;
}


WinDivertDev::~WinDivertDev()
{
    if(!_closed)
        WinDivertClose(_handle);
}


void WinDivertDev::setWinDivert()
{
    //for both ip and ipv6
    std::string filter = "(tcp.DstPort == " + std::to_string(_port) + " or tcp.SrcPort == " + std::to_string(ProxyServer::getListeningPort()) + ")";
    //if getLocalIpv6Address failed, that means that we don't have an ipv6 address
    //so we make the filter not stop ipv6
    if (!(ProxyServer::ipv6Available) && !(ProxyServer::ipv4Available))
    {
        filter += " and false";//not capture anything, if no ip is available
    }
    else if (!(ProxyServer::ipv6Available))
    {
        filter += " and ip";//only ipv4 if ipv6 not available
    }
    else if (!(ProxyServer::ipv4Available))
    {
        filter += " and ipv6";//only ipv6 if v4 not
    }

    // Open a WinDivert handle
    this->_handle = WinDivertOpen(filter.c_str(), this->_listenLayer, 0, 0);
    if (this->_handle == INVALID_HANDLE_VALUE) {
        std::cerr << "Error: Failed to open WinDivert handle (Error: " << GetLastError() << ")" << std::endl;
        throw std::exception("WinDivert Error!");
    }
    std::cout << "Monitoring all packets where: " << filter << std::endl;
}

void WinDivertDev::unsetWindivert()
{
    _closed = true;
    WinDivertClose(_handle);
}

//all about optimizations, 
WinDivertPacket* WinDivertDev::recv()
{
    static char* packet[BUFFER_SIZE] = { 0 };
    UINT packetLen = 0;
    

    WinDivertPacket* p = nullptr;
    WINDIVERT_ADDRESS addr = {};
    if (!WinDivertRecv(_handle, packet, BUFFER_SIZE, &packetLen, &addr))
    {
        std::cerr << "Error: Failed to read packet (Error: " << GetLastError() << ")" << std::endl;
        return (WinDivertPacket*)nullptr;
    }

    p = new WinDivertPacket((byte*)packet, packetLen, addr);
   
    memset(packet, 0, BUFFER_SIZE);

    return p;
}


void WinDivertDev::sendPacket(WinDivertPacket* packet)
{
    const bytes& raw = packet->getRaw();
    auto& addr = packet->getAddr();

    if (!WinDivertSend(_handle, raw.data(), (UINT)(raw.size()), NULL, &addr))
    {
        std::cerr << "Error: Failed to send packet (Error: " << GetLastError() << ")" << std::endl;
        throw std::exception("WinDivert Error!");
    }
}


bool WinDivertDev::validFilter(const std::string& filter, WINDIVERT_LAYER listenLayer)
{
    return WinDivertDev::validFilter(filter.c_str(), listenLayer);
}


bool WinDivertDev::validFilter(const char* filter, WINDIVERT_LAYER listenLayer)
{
    return WinDivertHelperCompileFilter(filter, listenLayer, NULL, 0, NULL, NULL);
}

