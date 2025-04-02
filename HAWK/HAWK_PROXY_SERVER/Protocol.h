#pragma once

#include <string>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <algorithm>
#include <vector>
#include <bitset>
#include <memory>
#include "../HAWK_TLS/TLSServer.h"
#include "includes/windivert.h"


typedef unsigned char byte;

#define KEY_NOT_FOUND -1

#define BITS_IN_BYTE 8
#define BYTES_IN_IP_ADDR 4
#define TCP_IP_HEADER 6
#define UDP_IP_HEADER 17
#define ICMP_IP_HEADER 1

#define ETHERNETHDR_SIZE 14

#define MACADDR_SIZE 6
#define ETHERTYPE_SIZE 2

typedef struct {
	byte DstAddr[6];
	byte SrcAddr[6]; 
	short EtherType; 
} NOTWINDIVERT_ETHERNETHDR;
typedef struct
{
	bool syn:1;
	bool ack:1;
	bool fin:1;
	bool urg:1;
	bool psh:1;
	bool chk:1;
	bool wnd:1;
	bool rst:1;
	bool ns:1;
} TCP_FLAGS;
//so cool, only takes 2 bytes
//this is only 9 bits


class Packet
{
public:
	Packet(const bytes& raw);
	Packet(const byte* raw, size_t size);
	Packet(const Packet& other);
	Packet();

	const WINDIVERT_IPHDR* getIpLayer() const;
	const WINDIVERT_IPV6HDR* getIpv6Layer() const;
	const WINDIVERT_TCPHDR* getTcpLayer() const;
	const WINDIVERT_UDPHDR* getUdpLayer() const;

	const WINDIVERT_ICMPHDR* getIcmpLayer() const;
	const WINDIVERT_ICMPV6HDR* getIcmpv6Layer() const;


	time_t getTimeStamp() const;

	std::string getProtocol() const;
	size_t getPacketSize() const;
	std::string getInfo() const;


	RGBColour getColour() const;


	unsigned int getPayloadSize();

	inline bytes getPayload() const
	{
		if (_payloadLen <= 0)
			return bytes();

		return this->_raw.substr(this->_raw.size() - this->_payloadLen, this->_payloadLen);

	}


	const bytes& getRaw() const;
	bool isTCP();

	TCP_FLAGS getTcpFlags() const;

	std::string getDstIp() const;
	std::string getSrcIp() const;

	std::string getSrc() const;
	std::string getDst() const;
	unsigned short getSrcPort() const;
	unsigned short getDstPort() const;


	std::string payloadHexView() const;

	friend std::ostream& operator<<(std::ostream& os, const Packet& p);

protected:
	void extractLayers();

	std::string ethernetProtocolToString() const;

	static std::string macToString(const byte* macAddr);
	static std::string bytesHexView(const bytes& data);

	bool _tcp;
	bytes _raw;
	
	WINDIVERT_ICMPHDR* _icmpHeader = NULL;
	WINDIVERT_ICMPV6HDR* _icmpv6Header = NULL;
	WINDIVERT_IPHDR* _ipHeader = NULL;
	WINDIVERT_IPV6HDR* _ipv6Header = NULL;
	WINDIVERT_TCPHDR* _tcpHeader = NULL;
	WINDIVERT_UDPHDR* _udpHeader = NULL;

	NOTWINDIVERT_ETHERNETHDR _ethernetHeader = {};
	bool hasEthernet = false;

	
	UINT _payloadLen = 0;


	time_t timeStamp;
};



class PcapPacket : public Packet
{
public:
	PcapPacket(const bytes& raw);
	PcapPacket(const byte* raw, size_t size);
	PcapPacket(const Packet& other);
	PcapPacket();
protected:
	void extractLayers();
};




class WinDivertPacket : public Packet
{
public:
	WinDivertPacket(const bytes& raw, WINDIVERT_ADDRESS addr);
	WinDivertPacket(const byte* raw, size_t size, WINDIVERT_ADDRESS addr);
	WinDivertPacket(const WinDivertPacket& other);
	WinDivertPacket();



	void setPacketSeqAck(const size_t newSeq, const size_t newAck);

	void setPacketDstIpPort(const std::string& newIp, const unsigned short newPort);
	void setPacketSrcIpPort(const std::string& newIp, const unsigned short newPort);



	void setPayload(const bytes& newPayload);

	WINDIVERT_ADDRESS& getAddr();


	void setOutbound(bool val);
	bool getOutbound();

protected:
	WINDIVERT_ADDRESS _addr;
	bool _outbound;
};




/*
*********************************************************************************************************
  _____  ______ _____  _____  ______ _____       _______ ______ _____
 |  __ \|  ____|  __ \|  __ \|  ____/ ____|   /\|__   __|  ____|  __ \
 | |  | | |__  | |__) | |__) | |__ | |       /  \  | |  | |__  | |  | |
 | |  | |  __| |  ___/|  _  /|  __|| |      / /\ \ | |  |  __| | |  | |
 | |__| | |____| |    | | \ \| |___| |____ / ____ \| |  | |____| |__| |
 |_____/|______|_|    |_|  \_\______\_____/_/    \_\_|  |______|_____/

*********************************************************************************************************
*/

/*
*********************************************************************************************************
  _____  ______ _____  _____  ______ _____       _______ ______ _____
 |  __ \|  ____|  __ \|  __ \|  ____/ ____|   /\|__   __|  ____|  __ \
 | |  | | |__  | |__) | |__) | |__ | |       /  \  | |  | |__  | |  | |
 | |  | |  __| |  ___/|  _  /|  __|| |      / /\ \ | |  |  __| | |  | |
 | |__| | |____| |    | | \ \| |___| |____ / ____ \| |  | |____| |__| |
 |_____/|______|_|    |_|  \_\______\_____/_/    \_\_|  |______|_____/

*********************************************************************************************************
*/


/*
*********************************************************************************************************
  _____  ______ _____  _____  ______ _____       _______ ______ _____
 |  __ \|  ____|  __ \|  __ \|  ____/ ____|   /\|__   __|  ____|  __ \
 | |  | | |__  | |__) | |__) | |__ | |       /  \  | |  | |__  | |  | |
 | |  | |  __| |  ___/|  _  /|  __|| |      / /\ \ | |  |  __| | |  | |
 | |__| | |____| |    | | \ \| |___| |____ / ____ \| |  | |____| |__| |
 |_____/|______|_|    |_|  \_\______\_____/_/    \_\_|  |______|_____/

*********************************************************************************************************
*/

//a field in a certain scheme, contains desc:description and size: size of field in bytes
typedef struct Field {
	Field(std::string desc, size_t size) : desc(desc), size(size) {}
	std::string desc;
	size_t size;
} Field;


//change (guy said, jonathan change)
class Schema : public std::vector<Field>
{
public:
	Schema() : std::vector<Field>() {}
	Schema(const std::initializer_list<Field>& init) : std::vector<Field>(init) {}

	unsigned int at(const std::string& key) const;
	void insert(const std::string& key, unsigned int val);

	bool find(const std::string& key) const;
};


const Schema UDP_SCHEMA =
{
		{"Source Port", 16},
		{"Destination Port", 16},
		{"Length", 16},
		{"Checksum", 16}
};
const Schema TCP_SCHEMA =
{
	{"Source Port", 16},
	{"Destination Port", 16},
	{"Sequence Number", 32},
	{"Acknowledgment Number", 32},
	{"Header length", 4},
	{"Reserved", 3},
	{"Flags", 9},
	{"Window Size", 16},
	{"Checksum", 16},
	{"Urgent Pointer", 16}
};
const Schema IP_SCHEMA =
{
	{"Version", 4},
	{"IHL", 4},
	{"TOS", 8},
	{"Length", 16},
	{"ID", 16},
	{"Flags", 3},
	{"Fragment Offset", 13},
	{"TTL", 8},
	{"Protocol", 8},
	{"Checksum", 16},
	{"Source IP", 32},
	{"Destination IP", 32}
};
const Schema EMPTY_SCHEMA =
{};


class Protocol
{
public:
	Protocol(const bytes& raw);
	Protocol(const char* raw, size_t size);

	const bytes getRaw() { return _raw; }

	friend std::ostream& operator<<(std::ostream& os, const Protocol& p);

protected:
	virtual std::string toString() const;

	bytes _raw;
};

class BinaryProtocol : public Protocol
{
public:
	BinaryProtocol(const bytes& raw, const Schema& sc = EMPTY_SCHEMA);
	BinaryProtocol(const char* raw, size_t size, const Schema& sc = EMPTY_SCHEMA);

	bool edit(const std::string& header, unsigned int data);
	unsigned int getVal(const std::string& header) const;
	const std::string getRaw() const;

protected:
	virtual std::string toString() const;
	void parse();

	std::string _binary;
	Schema _schema;
	Schema _content;
};


class UDP : public BinaryProtocol
{
public:
	UDP(const bytes& raw);
	UDP(const char* raw, size_t size);

};

class TCP : public BinaryProtocol
{
public:
	TCP(const bytes& raw);
	TCP(const char* raw, size_t size);

};

class IP : public BinaryProtocol
{
public:
	IP(const bytes& raw);
	IP(const char* raw, size_t size);

	static std::string ipAddrToStr(unsigned int addr);

private:
	virtual std::string toString() const override;
};



std::string stringToHexString(const std::string& input);
