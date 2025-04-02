#pragma once
#include "pcap.h"
#include <iostream>
#include <windows.h>
#include <iomanip>
#include <cstring>
#include <vector>
#include <unordered_map>
#include "../HAWK_PROXY_SERVER/Protocol.h"
#include "../HAWK_PROXY_SERVER/ProxyServer.hpp"


typedef pcap_if_t NetworkDevice;
typedef pcap_t DeviceHandle;
typedef struct pcap_pkthdr PacketInfo;
//ts -> unix timestamp of packet
//capLen -> /* length of portion present */
//len -> /* length of this packet (off wire) */

class PacketCapture 
{
public:
    PacketCapture(NetworkDevice* device);
    PacketCapture(bool debug);
    PacketCapture();

    const std::vector<std::string>& getAllDeviceNames();

    void listenDevice(const std::string& deviceFriendlyName);


    void halt();



    Packet* getPacket();
    
    



    ~PacketCapture();

    static double mbsCaptured();


private:
    void listen();
    void pushPacket(Packet* p);
    static void printConsole(unsigned char* param, const PacketInfo* header, const unsigned char* pkt_data);
    static void addPending(unsigned char* param, const PacketInfo* header, const unsigned char* pkt_data);
    static std::string turnGuidToCommonName(const std::string& guid);

    std::vector<std::string> _deviceNames;

    std::unordered_map<std::string, std::string> _deviceNameToGuid;


    LockFreeQueue<Packet> _pendingToView;

    NetworkDevice* _allDevices;
    NetworkDevice* _deviceToMonitor;

    std::string _deviceToMonitorName;

    bool _listening = false;
    

    DeviceHandle* _handle;

    static double mbCaptured;

};




