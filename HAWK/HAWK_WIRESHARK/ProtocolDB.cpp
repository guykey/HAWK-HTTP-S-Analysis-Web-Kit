#include "ProtocolDB.h"




const std::string ProtocolDB::portsJsonFile = "ports.lists.json";

json ProtocolDB::data;
bool ProtocolDB::initSuccess = false;


void ProtocolDB::init()
{
    if (initSuccess)
        return;
    try
    {
        std::ifstream f(ProtocolDB::portsJsonFile);
        ProtocolDB::data = json::parse(f);
        initSuccess = true;
    }
    catch (...)
    {
        ProtocolDB::initSuccess = false;
    }

}

std::string ProtocolDB::getTcpProtocol(unsigned short srcPort, unsigned short dstPort)
{
    std::string protocolDescription = "TCP";
    const unsigned short port = std::min(srcPort, dstPort);

    if (initSuccess)
    {
        if (data.contains(std::to_string(port)))//an entry for the port exists
        {
            auto entries = data[std::to_string(port)];
            for (auto& entry : entries)
            {
                if (entry["tcp"])
                {
                    protocolDescription = entry["description"];
                    if (protocolDescription == "Unassigned")
                        protocolDescription = "TCP";
                }
            }
        }
    }


    return protocolDescription;
}

std::string ProtocolDB::getUdpProtocol(unsigned short srcPort, unsigned short dstPort)
{
    std::string protocolDescription = "UDP";

    const unsigned short port = std::min(srcPort, dstPort);

    if (initSuccess)
    {
        if (data.contains(std::to_string(port)))//an entry for the port exists
        {
            auto entries = data[std::to_string(port)];
            for (auto& entry : entries)
            {
                if (entry["udp"])
                {
                    protocolDescription = entry["description"];
                    if (protocolDescription == "Unassigned")
                        protocolDescription = "UDP";
                }
            }
        }
    }


    return protocolDescription;
}
