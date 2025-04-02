#include "Communicator.h"





Communicator::Communicator(COMMUNICATION_TYPES typeOfCom) : _comType(typeOfCom)
{
}
Communicator::~Communicator()
{
}


SocketCommunicator::SocketCommunicator(SOCKET socket, bool ipv6) : Communicator(SOCKET_COM), _socket(socket), _isListen(false), _ipv6(ipv6)
{
}

SocketCommunicator::SocketCommunicator(bool ipv6) : Communicator(SOCKET_COM), _isListen(false), _ipv6(ipv6)
{
	if (ipv6)
		this->_socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	else
		this->_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

}

SocketCommunicator::SocketCommunicator(const std::string& port) : Communicator(SOCKET_COM), _isListen(true), _wsa()
{
	this->_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (this->_socket == INVALID_SOCKET)
		throw std::exception(__FUNCTION__ " - socket");

	struct sockaddr_in sa = { 0 };
	sa.sin_port = htons((u_short)(stoi(port))); // port that server will listen for
	sa.sin_family = AF_INET;   // must be AF_INET
	sa.sin_addr.s_addr = INADDR_ANY;


	if (::bind(this->_socket, (struct sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR)
		throw std::exception(__FUNCTION__ " - bind");

	if (::listen(this->_socket, SOMAXCONN) == SOCKET_ERROR)
		throw std::exception(__FUNCTION__ " - listen");

}

SocketCommunicator::SocketCommunicator(const std::string& port, const bool local, const bool ipv6) : Communicator(SOCKET_COM), _isListen(true), _wsa(), _ipv6(ipv6)
{
	if (_ipv6)
	{
		this->_socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		if (this->_socket == INVALID_SOCKET)
			throw std::exception(__FUNCTION__ " - socket");

		// Force IPv6-only mode
		int onlyIPv6 = 1;
		if (setsockopt(this->_socket, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&onlyIPv6, sizeof(onlyIPv6)) == SOCKET_ERROR)
			throw std::exception(__FUNCTION__ " - setsockopt IPV6_V6ONLY failed");

		struct sockaddr_in6 sa = { 0 };
		sa.sin6_family = AF_INET6;
		sa.sin6_port = htons((u_short)(stoi(port)));

		std::string ip = getLocalIPV6Address();
		if (inet_pton(AF_INET6, ip.c_str(), &sa.sin6_addr) != 1)
			throw std::exception(__FUNCTION__ " - inet_pton failed");

		std::cout << "Listening to ip: " << ip << std::endl;


		if (::bind(this->_socket, (struct sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR)
			throw std::exception(__FUNCTION__ " - bind");

		if (::listen(this->_socket, SOMAXCONN) == SOCKET_ERROR)
			throw std::exception(__FUNCTION__ " - listen");

	}
	else
	{
		this->_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (this->_socket == INVALID_SOCKET)
			throw std::exception(__FUNCTION__ " - socket");

		struct sockaddr_in sa = { 0 };
		sa.sin_port = htons((u_short)(stoi(port))); // port that server will listen for
		sa.sin_family = AF_INET;   // must be AF_INET

		//for divertor, ip needs to be our local ip
		std::string ip = getLocalIPAddress();
		inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
		//sa.sin_addr.s_addr = INADDR_ANY;

		if (::bind(this->_socket, (struct sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR)
			throw std::exception(__FUNCTION__ " - bind");

		if (::listen(this->_socket, SOMAXCONN) == SOCKET_ERROR)
			throw std::exception(__FUNCTION__ " - listen");
	}

}


SocketCommunicator::~SocketCommunicator()
{
	if (!_closed)
		closesocket(_socket);
}

void SocketCommunicator::closeSocket()
{
	if (!_closed)
		closesocket(this->_socket);
	_closed = true;
}

bool SocketCommunicator::connect(const std::string& dst, const std::string& port)
{
	if (!_ipv6)
	{
		// acctual handshake
		struct addrinfo hints, * result;//generate dst address
		ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		//do a dns lookup to turn the url into an ip
		int addrInfoRes = getaddrinfo(dst.c_str(), port.c_str(), &hints, &result);
		std::cout << "    Dns Lookup: " << dst << std::endl;
		if (!result)
		{
			std::cout << "      Failed!" << std::endl;
			throw std::exception("Failed To Connect!");
		}
		else
			std::cout << "      Success!" << std::endl;

		//connect to the dst server
		::connect(this->_socket, result->ai_addr, (int)result->ai_addrlen);
		freeaddrinfo(result);//free memory

		return true;
	}
	else
	{
		struct addrinfo hints, * result; // generate dst address
		ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = AF_INET6;  // Only look for IPv6 addresses
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;  // TCP connection

		// Perform a DNS lookup to turn the URL into an IP address
		int addrInfoRes = getaddrinfo(dst.c_str(), port.c_str(), &hints, &result);
		std::cout << "    DNS Lookup: " << dst << std::endl;

		if (addrInfoRes != 0 || !result) {
			std::cout << "      Failed!" << std::endl;
			throw std::exception("Failed To Connect!");
		}
		else {
			std::cout << "      Success!" << std::endl;
		}

		// Now connect to the destination server
		::connect(this->_socket, result->ai_addr, (int)result->ai_addrlen);
		freeaddrinfo(result);  // Free memory

		return true;
	}

}
SOCKET SocketCommunicator::accept(sockaddr* addr, int* addrLen)
{
	if (!this->_isListen)
		throw std::exception("Can't call accept on non-listening SocketCommunicator Instance!");

	return ::accept(this->_socket, addr, addrLen);
}

int SocketCommunicator::send(const bytes& data, size_t size)
{
	return ::send(this->_socket, (const char*)data.data(), (int)size, 0);
}
int SocketCommunicator::recv(bytes& buffer, size_t size)
{
	size_t bytesReceived = 0;
	int curr = 0;
	buffer.clear();
	buffer.resize(size);
	while (bytesReceived < size)
	{
		curr = ::recv(this->_socket, (char*)buffer.data() + bytesReceived, (int)(size - bytesReceived), 0);

		if (curr == 0)
		{
			throw std::runtime_error("Socket Closed");
		}
		else if (curr < 0)
		{
			int err = WSAGetLastError();
			if (err == WSAEWOULDBLOCK)
			{
				std::this_thread::sleep_for(std::chrono::milliseconds(1));
				continue;
			}
			else
			{
				perror("recv error");
				throw std::runtime_error("recv failed");
			}
		}
		bytesReceived += curr;
		if (bytesReceived < size)
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
	buffer.resize(bytesReceived);
	return (int)bytesReceived;
}

int SocketCommunicator::recvBuff(bytes& buffer)
{
	size_t bytesReceived = 0;
	int curr = 0;
	buffer.clear();
	const int RECV_SIZE = 4096;
	buffer.resize(RECV_SIZE);
	

	curr = ::recv(this->_socket, (char*)buffer.data() + bytesReceived, (int)(RECV_SIZE), 0);

	if (curr == 0)
	{
		throw std::runtime_error("Socket Closed");
	}
	else if (curr < 0)
	{
		int err = WSAGetLastError();
		if (err != WSAEWOULDBLOCK)
		{
			perror("recv error");
			throw std::runtime_error("recv failed");
		}

	}
	bytesReceived += curr;

	
	buffer.resize(bytesReceived);
	return (int)bytesReceived;
}

int SocketCommunicator::peek(bytes& buffer, size_t size)
{
	size_t bytesReceived = 0;

	buffer.clear();
	buffer.resize(size);

	bytesReceived = ::recv(this->_socket, (char*)buffer.data(), (int)size, MSG_PEEK);//will block, so no problem if no data
	if (bytesReceived == 0)
		throw std::exception("Socket Closed");

	return (int)bytesReceived;
}

void SocketCommunicator::bind()
{
	if (_ipv6)
	{
		sockaddr_in6 localAddr;
		memset(&localAddr, 0, sizeof(localAddr));

		localAddr.sin6_family = AF_INET6;
		localAddr.sin6_addr = in6addr_any;
		localAddr.sin6_port = htons(0);

		// Bind the socket
		if (::bind(this->_socket, (sockaddr*)&localAddr, sizeof(localAddr)) == SOCKET_ERROR)
			throw std::exception(__FUNCTION__ " - bind");

	}
	else
	{
		sockaddr_in localAddr;
		memset(&localAddr, 0, sizeof(localAddr));

		localAddr.sin_family = AF_INET;
		localAddr.sin_addr.s_addr = INADDR_ANY; // Bind to any available IP on the local machine
		localAddr.sin_port = 0;  // Use 0 to let the OS choose an available port

		if (::bind(this->_socket, (sockaddr*)&localAddr, sizeof(localAddr)) == SOCKET_ERROR)
			throw std::exception(__FUNCTION__ " - bind");
	}

}





SOCKET SocketCommunicator::getFD()
{
	return this->_socket;
}

unsigned short SocketCommunicator::getSrcPort()
{
	if (!_ipv6)
	{
		sockaddr_in localAddr;
		int addrLen = sizeof(localAddr);
		if (getsockname(this->_socket, (sockaddr*)&localAddr, &addrLen) == SOCKET_ERROR) {
			return 0;
		}

		return ntohs(localAddr.sin_port);
	}
	else
	{
		sockaddr_in6 localAddr;  // Use sockaddr_in6 for IPv6
		int addrLen = sizeof(localAddr);
		if (getsockname(this->_socket, (sockaddr*)&localAddr, &addrLen) == SOCKET_ERROR) {
			return 0;
		}
		return ntohs(localAddr.sin6_port);
	}

}

unsigned short SocketCommunicator::getDstPort()
{
	if (!_ipv6)
	{
		sockaddr_in clientAddr;
		int addrLen = sizeof(clientAddr);
		if (getpeername(this->_socket, (sockaddr*)&clientAddr, &addrLen) == SOCKET_ERROR) {
			return 0;
		}

		return ntohs(clientAddr.sin_port); // This is the client's source port
	}
	else
	{
		sockaddr_in6 clientAddr;  // Use sockaddr_in6 for IPv6
		int addrLen = sizeof(clientAddr);
		if (getpeername(this->_socket, (sockaddr*)&clientAddr, &addrLen) == SOCKET_ERROR) {
			std::cout << __FUNCTION__ << std::endl;
			return 0;
		}

		return ntohs(clientAddr.sin6_port);
	}

}


bool SocketCommunicator::isDataAvailable()
{
	u_long mode = 1; // Non-blocking mode
	ioctlsocket(this->_socket, FIONBIO, &mode);

	char buffer; // Small buffer to check if data is available
	int result = ::recv(this->_socket, &buffer, sizeof(buffer), MSG_PEEK); // Peek to check if data is available

	mode = 0; // blocking mode
	ioctlsocket(this->_socket, FIONBIO, &mode);

	return result > 0; // If result > 0, data is available
}

std::string getLocalIPAddress()
{
	static std::string ip = "";

	if (ip != "")
		return ip;
	WSAInitializer wsa;
	char hostname[256];
	if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) {
		throw std::exception("Failed to get hostname");
	}

	struct addrinfo hints = { 0 }, * res = nullptr;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
		throw std::exception("Failed to get local IP address");
	}

	char ipStr[INET_ADDRSTRLEN] = { 0 };
	struct sockaddr_in* addr = (struct sockaddr_in*)res->ai_addr;
	inet_ntop(AF_INET, &addr->sin_addr, ipStr, sizeof(ipStr));

	freeaddrinfo(res);
	return std::string(ipStr);
}

std::string getLocalIPV6Address()
{
	static std::string ip = "";

	if (ip != "")
		return ip;
	WSAInitializer wsa;
	std::vector<std::string> ipv6Addresses;
	PIP_ADAPTER_ADDRESSES pAddresses = NULL;
	ULONG outBufLen = 0;
	ULONG dwRetVal = 0;

	dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
	if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
		pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
		if (pAddresses == NULL) {
			std::cerr << "Memory allocation failed for adapter addresses." << std::endl;
			return "";
		}
	}
	else {
		std::cerr << "GetAdaptersAddresses failed (initial call), error: " << dwRetVal << std::endl;
		return "";
	}

	dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
	if (dwRetVal != NO_ERROR) {
		std::cerr << "GetAdaptersAddresses failed, error: " << dwRetVal << std::endl;
		free(pAddresses);
		return "";
	}

	for (PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses; pCurrAddresses != NULL; pCurrAddresses = pCurrAddresses->Next) {
		for (PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress; pUnicast != NULL; pUnicast = pUnicast->Next) {
			if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6) {
				if (pUnicast->SuffixOrigin == IpSuffixOriginRandom) { // Check for temporary address
					char ipAddress[INET6_ADDRSTRLEN];
					DWORD ipAddressLength = INET6_ADDRSTRLEN;
					if (WSAAddressToStringA(pUnicast->Address.lpSockaddr, pUnicast->Address.iSockaddrLength, NULL, ipAddress, &ipAddressLength) == 0) {
						ipv6Addresses.push_back(ipAddress);
					}
				}
			}
		}
	}

	free(pAddresses);

	if (!ipv6Addresses.empty()) {
		ip = ipv6Addresses[0];
		return ipv6Addresses[0]; // Return the first temporary address found
	}

	return ""; // No temporary IPv6 address found
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



StreamCommunicator::StreamCommunicator() : Communicator(IOSTREAM)
{
	_out = new bytesStream();
	_in = new bytesStream();
}

StreamCommunicator::~StreamCommunicator()
{
	delete _out;
	delete _in;
}

bytesStream& bytesStream::operator<<(const bytes& b)
{
	concat(b);

	return *this;
}

bytesStream& bytesStream::operator<<(const std::string& b)
{
	bytes by(b);

	*this << by;

	return *this;
}

bytesStream& bytesStream::operator<<(const char* b)
{
	bytes s(b);

	*this << s;

	return *this;
}

bytesStream& bytesStream::operator>>(bytes& b)
{

	if (b.size() > size())
	{
		b = *this;
		clear();
	}
	else
	{
		b = slice(0, b.size());
		this->erase(0, b.size());
	}

	return *this;
}

//read certain size from stream
//unsafe, need to add some exception to when reading when empty
int bytesStream::read(bytes& buffer, size_t size)
{
	size_t readSize = size > this->size() ? this->size() : size;

	// need to use mutex maybe
	while (this->size() <= 0) // wait until something new is in stream
		std::this_thread::sleep_for(std::chrono::milliseconds(100));

	buffer.clear();
	buffer.resize(readSize);

	memcpy((void*)buffer.data(), (void*)this->data(), readSize);
	this->erase(0, readSize);

	return (int)readSize;
}

int bytesStream::write(const bytes& buffer, size_t size)
{
	size_t writeSize = size > buffer.size() ? buffer.size() : size;
	this->concat(buffer.slice(0, writeSize));

	return (int)writeSize;
}

std::ostream& operator<<(std::ostream& os, const bytesStream& bs)
{
	os << bs.data();

	return os;
}


int StreamCommunicator::send(const bytes& data, size_t size)
{
	std::lock_guard<std::mutex> lockUpdate(this->_inLock);
	auto output = _out->write(data, size);
	this->_waitIn.notify_all();//notify waiters

	return output;
}

int StreamCommunicator::recv(bytes& buffer, size_t size)
{
	std::unique_lock<std::mutex> waitBuffer(this->_inLock);
	if (_in->empty() && size > 0)
	{
		this->_waitIn.wait(waitBuffer);
	}
	return _in->read(buffer, size);
}

StreamCommunicator* StreamCommunicator::createOtherSide()
{
	return new StreamCommunicator(*this);
}

StreamCommunicator::StreamCommunicator(const StreamCommunicator& sc) : Communicator(IOSTREAM)
{
	//but flipped!
	_out = sc._in;
	_in = sc._out;
}


