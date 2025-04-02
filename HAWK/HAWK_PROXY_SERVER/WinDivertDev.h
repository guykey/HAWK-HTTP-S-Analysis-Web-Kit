#pragma once

#include <iostream>
#include "Protocol.h"
#include "includes/windivert.h"
#pragma comment(lib, "WinDivert.lib")



#define BUFFER_SIZE 65535 
class WinDivertDev
{
public:
    WinDivertDev(unsigned short port, WINDIVERT_LAYER listenLayer = WINDIVERT_LAYER_NETWORK);
    ~WinDivertDev();

    void setWinDivert();
    void unsetWindivert();

    WinDivertPacket* recv(); // creates a new packet
    void sendPacket(WinDivertPacket* packet);

    static bool validFilter(const std::string& filter, WINDIVERT_LAYER listenLayer = WINDIVERT_LAYER_NETWORK);
    

private:

    bool _closed = false;

    static bool validFilter(const char* filter, WINDIVERT_LAYER listenLayer = WINDIVERT_LAYER_NETWORK);

    HANDLE _handle;
    
    WINDIVERT_LAYER _listenLayer;

    unsigned short _port;

};
