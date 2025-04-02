#pragma once
#include <iostream>
#include <string>
#include "../HAWK_WIRESHARK/json.hpp"
#include <fstream>

using json = nlohmann::json;


class ProtocolDB
{
public:
	static void init();
	static std::string getTcpProtocol(unsigned short srcPort, unsigned short dstPort);
	static std::string getUdpProtocol(unsigned short srcPort, unsigned short dstPort);

	static const std::string portsJsonFile;
private:

	static json data;
	static bool initSuccess;

};





