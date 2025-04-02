#include "Protocol.h"





Packet::Packet(const bytes& raw) : _raw(raw)
{
	this->timeStamp = time(NULL);
	extractLayers();
}
Packet::Packet(const byte* raw, size_t size) : _raw((byte*)raw, size)
{
	this->timeStamp = time(NULL);
	extractLayers();
}
Packet::Packet(const Packet& other) : _raw(other._raw), _tcp(other._tcp)
{
	this->timeStamp = other.timeStamp;
	extractLayers();
}
Packet::Packet() : _raw("")
{
	this->timeStamp = time(NULL);
	_tcp = false;

}

//this is fucking stupid
PcapPacket::PcapPacket(const bytes& raw) : Packet(raw)
{
	this->extractLayers();
}

PcapPacket::PcapPacket(const byte* raw, size_t size) : Packet(raw, size)
{
	this->extractLayers();
}

PcapPacket::PcapPacket(const Packet& other) : Packet(other)
{
	this->extractLayers();
}

PcapPacket::PcapPacket()
{
}

//ok, sorry, this is really fucking dumb
//didn't really want to rewrite a whole PcapPacket class
//so we just change this function
//but it still calls Packet::extractLayers which will crash
//the problem is that npcap gives us the packet with the ethernet layer, and windivert doesn't expect that
//but i dont want to remake the packet parser stuff
void PcapPacket::extractLayers()
{
	UINT8 protocol = 0;
	PVOID payload = NULL;
	//skip the ethernet layer
	const byte* startPacket = (byte*)(this->_raw.data() + ETHERNETHDR_SIZE);
	
	//parse ethernet layer
	memcpy((this->_ethernetHeader.DstAddr), this->_raw.data(), MACADDR_SIZE);
	memcpy((this->_ethernetHeader.SrcAddr), this->_raw.data() + MACADDR_SIZE, MACADDR_SIZE);

	uint16_t etherTypeNetworkOrder;
	memcpy(&etherTypeNetworkOrder, this->_raw.data() + (MACADDR_SIZE * 2), ETHERTYPE_SIZE);
	this->_ethernetHeader.EtherType = ntohs(etherTypeNetworkOrder);
	this->hasEthernet = true;

	// Parse the input packet
	if (!WinDivertHelperParsePacket(startPacket, (UINT)(this->_raw.size()), &_ipHeader, &_ipv6Header,
		&protocol, &_icmpHeader, &_icmpv6Header, &_tcpHeader, &_udpHeader,
		&payload, &_payloadLen, NULL, NULL)) {
		std::cerr << "Failed to parse packet!" << std::endl;
		return;
	}

	if (_tcpHeader)
		_tcp = true;
	else
		_tcp = false;
}


// ***** Packet Implementation *****

WinDivertPacket::WinDivertPacket(const bytes& raw, const WINDIVERT_ADDRESS addr) : Packet(raw), _addr(addr)
{
	_outbound = _addr.Outbound;

}
WinDivertPacket::WinDivertPacket(const byte* raw, size_t size, const WINDIVERT_ADDRESS addr) : Packet(raw, size), _addr(addr)
{
	_outbound = _addr.Outbound;

}

WinDivertPacket::WinDivertPacket() : Packet()
{
	_addr = {};
	_outbound = false;
}

//deep copy
WinDivertPacket::WinDivertPacket(const WinDivertPacket& other) : Packet(other), _addr(other._addr)
{
	_outbound = _addr.Outbound;
}


const WINDIVERT_IPHDR* Packet::getIpLayer() const
{
	return this->_ipHeader;
}

const WINDIVERT_IPV6HDR* Packet::getIpv6Layer() const
{
	return this->_ipv6Header;
}

const WINDIVERT_TCPHDR* Packet::getTcpLayer() const
{
	return this->_tcpHeader;
}

const WINDIVERT_UDPHDR* Packet::getUdpLayer() const
{
	return this->_udpHeader;
}

const WINDIVERT_ICMPHDR* Packet::getIcmpLayer() const
{
	return this->_icmpHeader;
}

const WINDIVERT_ICMPV6HDR* Packet::getIcmpv6Layer() const
{
	return this->_icmpv6Header;
}

time_t Packet::getTimeStamp() const
{
	return this->timeStamp;
}

std::string Packet::getProtocol() const
{
	static std::string protocol = "UNKNOWN";
	protocol = "UNKNOWN";
	if (_tcpHeader)
		protocol = ProtocolDB::getTcpProtocol(this->getSrcPort(), this->getDstPort());
	else if (_udpHeader)
		protocol = ProtocolDB::getUdpProtocol(this->getSrcPort(), this->getDstPort());
	else if (_icmpHeader)
		protocol = "ICMP";
	else if (_icmpv6Header)
		protocol = "ICMPV6";
	else if (hasEthernet)
		protocol = ethernetProtocolToString();
	
	
	return protocol;
}

size_t Packet::getPacketSize() const
{
	return this->_raw.size();
}

std::string Packet::getInfo() const
{
	unsigned short srcPort = 0, dstPort = 0;
	static std::string info = "";
	info = "";
	srcPort = this->getSrcPort();
	dstPort = this->getDstPort();
	if (dstPort && srcPort)
	{
		info += std::to_string(srcPort) + " -> " + std::to_string(dstPort);
		if (_tcpHeader)
			info += " TCP";
		if (_udpHeader)
			info += " UDP";
	}
	else
	{
		info += "NO PORTS";
	}

	if (_tcpHeader)
	{
		auto tcpFlags = this->getTcpFlags();
		if (tcpFlags.syn)
			info += " SYN";
		if (tcpFlags.fin)
			info += " FIN";
		if (tcpFlags.psh)
			info += " PSH";
		if (tcpFlags.ack)
			info += " ACK";
		if (tcpFlags.rst)
			info += " RST";
		if (tcpFlags.urg)
			info += " URG";
	}
	


	return info;
}


unsigned int Packet::getPayloadSize()
{
	return this->_payloadLen;
}



TCP_FLAGS Packet::getTcpFlags() const
{
	TCP_FLAGS flags = { 0 };
	memset(&flags, 0, sizeof(TCP_FLAGS));
	if (_tcpHeader) {
		flags.ack = _tcpHeader->Ack;
		flags.fin = _tcpHeader->Fin;
		flags.syn = _tcpHeader->Syn;
		flags.psh = _tcpHeader->Psh;
		flags.rst = _tcpHeader->Rst;
		flags.urg = _tcpHeader->Urg;
	}

	return flags;
}




const bytes& Packet::getRaw() const
{
	return _raw;
}
bool Packet::isTCP()
{
	return _tcp;
}





std::string Packet::getDstIp() const
{
	if (_ipHeader)
	{
		struct in_addr ipAddr;
		ipAddr.s_addr = _ipHeader->DstAddr;

		std::string addr;
		addr.resize(INET_ADDRSTRLEN);
		if (inet_ntop(AF_INET, &ipAddr, (PSTR)addr.data(), addr.size()) == nullptr) {
			return "(Unknown)";
		}

		return addr;

	}
	if (_ipv6Header)
	{
		auto addr = _ipv6Header->DstAddr;
		struct in6_addr ipv6Addr;
		// Copy UINT32 array into the in6_addr structure
		memcpy(&ipv6Addr, addr, sizeof(ipv6Addr));
		std::string addrString;
		addrString.resize(INET6_ADDRSTRLEN);
		if (inet_ntop(AF_INET6, &ipv6Addr, (PSTR)addrString.data(), addrString.size()) == nullptr) {
			return "(Unknown)";
		}
		return addrString;
	}
	return "(Unknown)";
}

std::string Packet::getSrcIp() const
{
	if (_ipHeader)
	{
		struct in_addr ipAddr;
		ipAddr.s_addr = _ipHeader->SrcAddr;

		std::string addr;
		addr.resize(INET_ADDRSTRLEN);
		if (inet_ntop(AF_INET, &ipAddr, (PSTR)addr.data(), addr.size()) == nullptr) {
			return "(Unknown)";
		}
		return addr;

	}
	if (_ipv6Header)
	{
		auto addr = _ipv6Header->SrcAddr;
		struct in6_addr ipv6Addr;
		// Copy UINT32 array into the in6_addr structure
		memcpy(&ipv6Addr, addr, sizeof(ipv6Addr));
		std::string addrString;
		addrString.resize(INET6_ADDRSTRLEN);
		if (inet_ntop(AF_INET6, &ipv6Addr, (PSTR)addrString.data(), addrString.size()) == nullptr) {
			return "(Unknown)";
		}
		return addrString;
	}
	return "(Unknown)";
}

std::string Packet::getSrc() const
{
	static const std::string notFound = "(Unknown)";
	std::string src = getSrcIp();
	if (src == notFound && hasEthernet)
	{
		src = macToString(this->_ethernetHeader.SrcAddr);
	}
	return src;
}

std::string Packet::getDst() const
{
	static const std::string notFound = "(Unknown)";
	std::string dst = getDstIp();
	if (dst == notFound && hasEthernet)
	{
		dst = macToString(this->_ethernetHeader.DstAddr);
	}
	return dst;
}

unsigned short Packet::getSrcPort() const
{

	if (_tcpHeader)
	{
		unsigned short srcPort = ntohs(_tcpHeader->SrcPort);
		return srcPort;
	}
	else if (_udpHeader)
	{
		unsigned short srcPort = ntohs(_udpHeader->SrcPort);
		return srcPort;
	}
	return 0;
}

unsigned short Packet::getDstPort() const
{
	if (_tcpHeader)
	{
		unsigned short srcPort = ntohs(_tcpHeader->DstPort);
		return srcPort;
	}
	else if (_udpHeader)
	{
		unsigned short srcPort = ntohs(_udpHeader->DstPort);
		return srcPort;
	}
	return 0;
}

std::string Packet::payloadHexView() const
{
	const bytes& headers = this->_raw.slice(0, this->_raw.size() - this->_payloadLen);
	const bytes& payload = this->getPayload();

	std::string hexView = "HEADERS\n" + Packet::bytesHexView(headers);
	hexView += "\n\nPAYLOAD\n";
	hexView += Packet::bytesHexView(this->getPayload());

	return hexView;

}

WINDIVERT_ADDRESS& WinDivertPacket::getAddr()
{
	return this->_addr;
}

void WinDivertPacket::setOutbound(bool val)
{
	_outbound = val;
}

bool WinDivertPacket::getOutbound()
{
	return _outbound;
}



void Packet::extractLayers()
{
	UINT8 protocol = 0;
	PVOID payload = NULL;

	// Parse the input packet
	if (!WinDivertHelperParsePacket(this->_raw.data(), (UINT)(this->_raw.size()), &_ipHeader, &_ipv6Header,
		&protocol, &_icmpHeader, &_icmpv6Header, &_tcpHeader, &_udpHeader,
		&payload, &_payloadLen, NULL, NULL)) {
		std::cerr << "Failed to parse packet!" << std::endl;
		return;
	}

	if (_tcpHeader)
		_tcp = true;
	else
		_tcp = false;

}

std::string Packet::ethernetProtocolToString() const
{
	std::string protocol = "(Unknown)";
	if (hasEthernet)
	{
		switch (this->_ethernetHeader.EtherType) {
		case 0x0800:  protocol = "IPv4"; break;
		case 0x0806:  protocol = "ARP"; break;
		case 0x0842:  protocol = "WoL"; break;  // Wake-on-LAN
		case 0x22EA:  protocol = "SRP"; break;  // Stream Reservation Protocol
		case 0x22F0:  protocol = "AVTP"; break; // Audio Video Transport Protocol
		case 0x22F3:  protocol = "TRILL"; break; // IETF TRILL Protocol
		case 0x6002:  protocol = "MOP RC"; break; // DEC MOP RC
		case 0x6003:  protocol = "DECnet IV"; break; // DECnet Phase IV, DNA Routing
		case 0x6004:  protocol = "LAT"; break; // DEC LAT
		case 0x8035:  protocol = "RARP"; break; // Reverse Address Resolution Protocol
		case 0x809B:  protocol = "EtherTalk"; break; // AppleTalk (EtherTalk)
		case 0x80D5:  protocol = "LLC PDU"; break; // LLC PDU (IBM SNA)
		case 0x80F3:  protocol = "AARP"; break; // AppleTalk ARP
		case 0x8100:  protocol = "VLAN"; break; // VLAN (IEEE 802.1Q)
		case 0x8102:  protocol = "SLPP"; break; // Simple Loop Prevention Protocol
		case 0x8103:  protocol = "VLACP"; break; // Virtual Link Aggregation Control Protocol
		case 0x8137:  protocol = "IPX"; break; // IPX
		case 0x8204:  protocol = "Qnet"; break; // QNX Qnet
		case 0x86DD:  protocol = "IPv6"; break; // Internet Protocol Version 6
		case 0x8808:  protocol = "Ethernet FC"; break; // Ethernet flow control
		case 0x8809:  protocol = "Ethernet Slow"; break; // Ethernet Slow Protocols
		case 0x8819:  protocol = "CobraNet"; break; // CobraNet
		case 0x8847:  protocol = "MPLS UC"; break; // MPLS unicast
		case 0x8848:  protocol = "MPLS MC"; break; // MPLS multicast
		case 0x8863:  protocol = "PPPoE Discovery"; break; // PPPoE Discovery Stage
		case 0x8864:  protocol = "PPPoE Session"; break; // PPPoE Session Stage
		case 0x887B:  protocol = "HomePlug 1.0"; break; // HomePlug 1.0 MME
		case 0x888E:  protocol = "EAPoLAN"; break; // EAP over LAN (IEEE 802.1X)
		case 0x8892:  protocol = "PROFINET"; break; // PROFINET Protocol
		case 0x889A:  protocol = "HyperSCSI"; break; // HyperSCSI (SCSI over Ethernet)
		case 0x88A2:  protocol = "ATAoE"; break; // ATA over Ethernet
		case 0x88A4:  protocol = "EtherCAT"; break; // EtherCAT Protocol
		case 0x88A8:  protocol = "S-Tag"; break; // Service VLAN tag identifier (S-Tag)
		case 0x88AB:  protocol = "Ethernet Powerlink"; break; // Ethernet Powerlink
		case 0x88B8:  protocol = "GOOSE"; break; // GOOSE (Generic Object Oriented Substation Event)
		case 0x88B9:  protocol = "GSE"; break; // GSE (Generic Substation Events)
		case 0x88BA:  protocol = "SV"; break; // Sampled Value Transmission
		case 0x88BF:  protocol = "RoMON"; break; // MikroTik RoMON
		case 0x88CC:  protocol = "LLDP"; break; // Link Layer Discovery Protocol
		case 0x88CD:  protocol = "SERCOS III"; break; // SERCOS III
		case 0x88E1:  protocol = "HomePlug GP"; break; // HomePlug Green PHY
		case 0x88E3:  protocol = "MRP"; break; // Media Redundancy Protocol (IEC62439-2)
		case 0x88E5:  protocol = "MACsec"; break; // IEEE 802.1AE MAC security
		case 0x88E7:  protocol = "PBB"; break; // Provider Backbone Bridges (IEEE 802.1ah)
		case 0x88F7:  protocol = "PTP"; break; // Precision Time Protocol
		case 0x88F8:  protocol = "NC-SI"; break; // NC-SI
		case 0x88FB:  protocol = "PRP"; break; // Parallel Redundancy Protocol
		case 0x8902:  protocol = "CFM"; break; // IEEE 802.1ag Connectivity Fault Management
		case 0x8906:  protocol = "FCoE"; break; // Fibre Channel over Ethernet
		case 0x8914:  protocol = "FCoE IP"; break; // FCoE Initialization Protocol
		case 0x8915:  protocol = "RoCE"; break; // RDMA over Converged Ethernet
		case 0x891D:  protocol = "TTE"; break; // TTEthernet Protocol Control Frame
		case 0x893A:  protocol = "1905.1"; break; // IEEE Protocol 1905.1
		case 0x892F:  protocol = "HSR"; break; // High-availability Seamless Redundancy
		case 0x9000:  protocol = "Ethernet Config Test"; break; // Ethernet Configuration Testing Protocol
		case 0xF1C1:  protocol = "Redundancy Tag"; break; // Redundancy Tag (IEEE 802.1CB Frame Replication)
		}
	}

	return protocol;
}

std::string Packet::macToString(const byte* macAddr)
{
	char macStr[18];  // MAC address string (6 bytes * 2 hex chars + 5 colons + null terminator)
	snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
		macAddr[0], macAddr[1], macAddr[2],
		macAddr[3], macAddr[4], macAddr[5]);
	return std::string(macStr);
}

std::string Packet::bytesHexView(const bytes& data)
{
	std::ostringstream hexStream;
	for (size_t i = 0; i < data.size(); i++) {
		if (i % 16 == 0 && i != 0) hexStream << "\n"; // New line every 16 bytes

		hexStream << std::hex << std::setfill('0') << std::setw(2)
			<< static_cast<int>(static_cast<unsigned char>(data[i])) << " ";

		if (i % 16 == 15 || i == data.size() - 1) { // Print ASCII
			size_t start = (i / 16) * 16;  // Start of this hex line

			// Align ASCII representation properly
			size_t extraSpaces = (15 - (i % 16)) * 3 + 2;  // Align ASCII column
			hexStream << std::string(extraSpaces, ' ');

			// Print ASCII characters
			for (size_t j = start; j <= i; j++) {
				hexStream << (std::isprint(data[j]) ? static_cast<char>(data[j]) : '.');
			}
		}
	}

	return hexStream.str(); // Convert stream to string
}


void WinDivertPacket::setPacketDstIpPort(const std::string& newIp, const unsigned short newPort)
{
	if (_tcpHeader && _ipHeader) {
		struct in_addr newDstAddr;
		if (inet_pton(AF_INET, newIp.c_str(), &newDstAddr) != 1)//failed to turn string ip to addr
			return;

		//change the ip and dst port
		_ipHeader->DstAddr = newDstAddr.S_un.S_addr;
		_tcpHeader->DstPort = htons(newPort);
		// Fix checksums
		WinDivertHelperCalcChecksums((void*)this->_raw.data(), (UINT)(this->_raw.size()), &(this->_addr), 0);
	}
	else if (_tcpHeader && _ipv6Header)
	{
		struct in6_addr newDstAddr;
		if (inet_pton(AF_INET6, newIp.c_str(), &newDstAddr) != 1) // Failed to convert string to IPv6 address
			return;

		// Change the destination IPv6 address and port
		memcpy(_ipv6Header->DstAddr, &(newDstAddr.s6_addr), sizeof(struct in6_addr)); // Correct way to set IPv6 address
		_tcpHeader->DstPort = htons(newPort);

		// Fix checksums
		WinDivertHelperCalcChecksums((void*)this->_raw.data(), (UINT)(this->_raw.size()), &(this->_addr), 0);
	}

}

void WinDivertPacket::setPacketSrcIpPort(const std::string& newIp, const unsigned short newPort)
{
	if (_tcpHeader && _ipHeader) {
		struct in_addr newSrcAddr;
		if (inet_pton(AF_INET, newIp.c_str(), &newSrcAddr) != 1)//failed to turn string ip to addr
			return;
		//change the ip and dst port
		_ipHeader->SrcAddr = newSrcAddr.S_un.S_addr;
		_tcpHeader->SrcPort = htons(newPort);
		// Fix checksums
		WinDivertHelperCalcChecksums((void*)this->_raw.data(), (UINT)(this->_raw.size()), &(this->_addr), 0);
	}
	else if (_tcpHeader && _ipv6Header)
	{
		struct in6_addr newSrcAddr;
		if (inet_pton(AF_INET6, newIp.c_str(), &newSrcAddr) != 1) // Failed to convert string to IPv6 address
			return;

		// Change the destination IPv6 address and port
		memcpy(_ipv6Header->SrcAddr, &newSrcAddr, sizeof(struct in6_addr)); // Correct way to set IPv6 address
		_tcpHeader->SrcPort = htons(newPort);

		// Fix checksums
		WinDivertHelperCalcChecksums((void*)this->_raw.data(), (UINT)(this->_raw.size()), &(this->_addr), 0);
	}
}

RGBColour Packet::getColour() const
{
	std::string protocol = getProtocol();

	if (protocol == "TCP") return { 180, 100, 100 };      // Duller red for TCP
	if (protocol == "UDP") return { 100, 100, 180 };      // Duller blue for UDP
	if (protocol == "ICMP") return { 100, 180, 100 };     // Duller green for ICMP
	if (protocol == "ICMPV6") return { 100, 180, 150 };   // Duller teal for ICMPv6
	if (protocol == "IPv4") return { 180, 140, 80 };      // Duller orange for IPv4
	if (protocol == "IPv6") return { 130, 100, 130 };     // Duller purple for IPv6
	if (protocol == "ARP") return { 200, 200, 80 };       // Duller yellow for ARP
	if (protocol == "RARP") return { 200, 170, 60 };      // Duller dark yellow for RARP
	if (protocol == "VLAN") return { 90, 60, 130 };       // Duller indigo for VLAN
	if (protocol == "Ethernet") return { 120, 120, 120 };  // Duller gray for Ethernet
	if (protocol == "PPPoE Discovery") return { 100, 200, 200 }; // Duller cyan for PPPoE Discovery
	if (protocol == "PPPoE Session") return { 100, 120, 180 }; // Duller light blue for PPPoE Session

	return { 180, 180, 180 };  // Default to duller gray for unknown protocols
}



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









void WinDivertPacket::setPacketSeqAck(const size_t newSeq, const size_t newAck)
{
	if (_tcpHeader) {
		// Modify sequence and acknowledgment numbers
		UINT32 oldSeq = ntohl(_tcpHeader->SeqNum);
		UINT32 oldAck = ntohl(_tcpHeader->AckNum);

		_tcpHeader->SeqNum = htonl((u_long)(newSeq));
		_tcpHeader->AckNum = htonl((u_long)(newAck));

		// Fix checksums
		WinDivertHelperCalcChecksums((void*)this->_raw.data(), (UINT)(this->_raw.size()), &(this->_addr), 0);
	}
}










//does this work?
//deprecated
void WinDivertPacket::setPayload(const bytes& newPayload)
{
	UINT ipHeaderSize = 0;
	UINT transportHeaderSize = 0;
	UINT newPacketLen = 0;

	if (_ipHeader) {
		ipHeaderSize = _ipHeader->HdrLength * 4;
	}
	else if (_ipv6Header) {
		ipHeaderSize = sizeof(WINDIVERT_IPV6HDR);  // IPv6 has a fixed header size
	}
	transportHeaderSize = (_tcpHeader) ? (_tcpHeader->HdrLength * 4) : ((_udpHeader) ? sizeof(WINDIVERT_UDPHDR) : 0);
	newPacketLen = (UINT)(ipHeaderSize + transportHeaderSize + (UINT)(newPayload.size()));


	bytes newPacket((size_t)newPacketLen);


	if (_ipHeader || _ipv6Header) {
		memcpy((void*)newPacket.data(), (void*)this->_raw.data(), ipHeaderSize);
	}


	if (_tcpHeader || _udpHeader) {
		memcpy((void*)(newPacket.data() + ipHeaderSize), (void*)(this->_raw.data() + ipHeaderSize), transportHeaderSize);
	}


	memcpy((void*)(newPacket.data() + ipHeaderSize + transportHeaderSize), newPayload.data(), newPayload.size());

	if (_ipHeader) {
		WINDIVERT_IPHDR* newIpHeader = (WINDIVERT_IPHDR*)newPacket.data();
		newIpHeader->Length = htons((u_short)newPacketLen);
	}

	if (_udpHeader) {
		WINDIVERT_UDPHDR* newUdpHeader = (WINDIVERT_UDPHDR*)(newPacket.data() + ipHeaderSize);
		newUdpHeader->Length = htons((u_short)(sizeof(WINDIVERT_UDPHDR) + (UINT)(newPayload.size())));
		newUdpHeader->Checksum = 0;
	}
	if (_tcpHeader) {
		WINDIVERT_TCPHDR* newTcpHeader = (WINDIVERT_TCPHDR*)(newPacket.data() + ipHeaderSize);
		newTcpHeader->Checksum = 0;
	}

	// Recalculate Checksums
	WinDivertHelperCalcChecksums((void*)newPacket.data(), newPacketLen, &(this->_addr), 0);

	this->_raw.clear();
	this->_raw = newPacket;
	//reset the headers
	this->_ipHeader = NULL;
	this->_ipv6Header = NULL;
	this->_tcpHeader = NULL;
	this->_udpHeader = NULL;

	this->extractLayers();
}




std::ostream& operator<<(std::ostream& os, const Packet& p)
{
	/*
	os << "***** IP *****\n";
	os << *p._ip << "\n\n";

	if (p._tcp)
		os << "***** TCP *****\n";
	else
		os << "***** UDP *****\n";

	os << *p._transport << "\n\n";

	if (p._load)
	{
		os << "***** Load *****\n";
		os << *p._load << "\n\n";
	}
	*/

	return os;
}









//fookin stupid




// ***** Helper *****

std::string stringToHexString(const std::string& input)
{
	std::ostringstream hexStream;
	hexStream << std::hex << std::setfill('0'); // Set to hexadecimal and zero-padding

	for (unsigned char c : input) {
		hexStream << std::setw(2) << static_cast<int>(c);
	}

	return hexStream.str();
}


unsigned int Schema::at(const std::string& key) const
{
	auto it = std::find_if(begin(), end(),
		[&key](const Field& item)
		{
			return item.desc == key;
		});

	if (it != end())
	{
		return (unsigned int)(it->size);
	}

	return KEY_NOT_FOUND;
}

void Schema::insert(const std::string& key, unsigned int val)
{
	auto it = std::find_if(begin(), end(),
		[&key](const Field& item)
		{
			return item.desc == key;
		});

	if (it != end())
	{
		it->size = val;
	}
	else
	{
		this->emplace_back(key, val);
	}

}

bool Schema::find(const std::string& key) const
{
	return at(key) != KEY_NOT_FOUND;
}


//

// ***** Protocol Implementation *****
Protocol::Protocol(const bytes& raw) : _raw(raw)
{
}
Protocol::Protocol(const char* raw, size_t size) : _raw((byte*)raw, size)
{
}

std::string Protocol::toString() const
{
	return _raw;
}


BinaryProtocol::BinaryProtocol(const bytes& raw, const Schema& sc) : Protocol(raw), _schema(sc)
{
	parse();
}

BinaryProtocol::BinaryProtocol(const char* raw, size_t size, const Schema& sc) : Protocol(raw, size), _schema(sc)
{
	parse();
}

bool BinaryProtocol::edit(const std::string& header, unsigned int data)
{
	if (_content.find(header))
	{
		std::cerr << "Binary Protocol (edit()): Unable to find header: " << header << std::endl;
		return false;
	}

	_content.insert(header, data);
	return true;
}

unsigned int BinaryProtocol::getVal(const std::string& header) const
{
	if (not _content.find(header))
	{
		std::cerr << "Binary Protocol (getVal()): Unable to find header: " << header << std::endl;
		return NULL;
	}

	return _content.at(header);
}

const std::string BinaryProtocol::getRaw() const
{
	return _raw;
}

void BinaryProtocol::parse()
{

	for (unsigned char c : _raw)
	{
		_binary += std::bitset<BITS_IN_BYTE>(c).to_string(); // Convert each character to 8-bit binary
	}

	auto it = _schema.begin();
	size_t offset = 0, size = 0; // the offest and size are in bits!
	std::string bin;
	//NO!!!

	for (it; it != _schema.end(); it++)
	{
		size = it->size;

		bin = _binary.substr(offset, size);
		_content.insert(it->desc, std::stoul(bin, nullptr, 2)); // base 2

		offset += size;
	}
}

std::string BinaryProtocol::toString() const
{
	if (_content.size() == 0)
		return _raw;

	auto it = _content.begin();
	std::string output = "";

	for (it; it != _content.end(); it++)
	{
		output += it->desc;
		output += ": ";
		output += std::to_string(it->size);
		output += '\n';
	}

	return output;
}


UDP::UDP(const bytes& raw) : BinaryProtocol(raw, UDP_SCHEMA)
{
}
UDP::UDP(const char* raw, size_t size) : BinaryProtocol(raw, size, UDP_SCHEMA)
{
}

TCP::TCP(const bytes& raw) : BinaryProtocol(raw, TCP_SCHEMA)
{
}
TCP::TCP(const char* raw, size_t size) : BinaryProtocol(raw, size, TCP_SCHEMA)
{
}

IP::IP(const bytes& raw) : BinaryProtocol(raw, IP_SCHEMA)
{
}
IP::IP(const char* raw, size_t size) : BinaryProtocol(raw, size, IP_SCHEMA)
{
}


std::string IP::ipAddrToStr(unsigned int addr)
{
	std::string newAddr = "";
	int c;

	for (int i = 0; i < BYTES_IN_IP_ADDR; i++)
	{
		c = addr & 0xFF; // first byte

		newAddr = std::to_string(c) + newAddr;

		if (i < BYTES_IN_IP_ADDR - 1) // not last one
			newAddr.insert(newAddr.begin(), '.');

		addr >>= BITS_IN_BYTE;
	}

	return newAddr;
}
std::string IP::toString() const
{
	auto it = _content.begin();
	std::string output = "";

	for (it; it != _content.end(); it++)
	{
		output += it->desc;
		output += ": ";

		if (it->desc.find("IP") != std::string::npos)
		{ // found
			output += ipAddrToStr((unsigned int)(it->size));
		}
		else
		{
			output += std::to_string(it->size);
		}

		output += '\n';
	}

	return output;
}

std::ostream& operator<<(std::ostream& os, const Protocol& p)
{
	os << p.toString();
	return os;
}


