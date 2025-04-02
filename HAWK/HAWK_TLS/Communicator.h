#pragma once

#include "constants.hpp"
#include "../HAWK_PROXY_SERVER/WSA.h"

#include <iphlpapi.h>
#include <ws2tcpip.h>

#pragma comment(lib, "iphlpapi.lib")

#include <mutex>
#include <exception>


enum COMMUNICATION_TYPES { SOCKET_COM, IOSTREAM };

class Communicator
{
public:
	virtual ~Communicator();

	virtual int send(const bytes& data, size_t size) = 0;
	virtual int recv(bytes& buffer, size_t size) = 0;

	COMMUNICATION_TYPES getType() { return _comType; }

protected:
	Communicator(COMMUNICATION_TYPES typeOfCom);
private:
	COMMUNICATION_TYPES _comType;
};



class SocketCommunicator : public Communicator
{
public:
	SocketCommunicator(SOCKET socket, bool ipv6 = false);
	SocketCommunicator(bool ipv6 = false);
	SocketCommunicator(const std::string& port);
	SocketCommunicator(const std::string& port, const bool local, const bool ipv6 = false);

	virtual ~SocketCommunicator() override;

	void closeSocket();


	bool connect(const std::string& dst, const std::string& port);
	SOCKET accept(sockaddr* addr = NULL, int* addrLen = NULL);

	virtual int send(const bytes& data, size_t size) override;
	virtual int recv(bytes& buffer, size_t size) override;
	int recvBuff(bytes& buffer);

	int peek(bytes& buffer, size_t size);

	void bind();//stupid

	SOCKET getFD();

	unsigned short getSrcPort();
	unsigned short getDstPort();
	bool isDataAvailable();

protected:

	bool _closed = false;

	SOCKET _socket;
	WSAInitializer _wsa;
	const bool _isListen;

	bool _ipv6 = false;
};


std::string getLocalIPAddress();
std::string getLocalIPV6Address();


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



class StreamCommunicator : public Communicator
{
public:
	StreamCommunicator();
	~StreamCommunicator();

	virtual int send(const bytes& data, size_t size) override;
	virtual int recv(bytes& buffer, size_t size) override;

	StreamCommunicator* createOtherSide();

protected:
	StreamCommunicator(const StreamCommunicator& sc);

	bytesStream* _in;
	bytesStream* _out;

	std::mutex _inLock;
	std::condition_variable _waitIn;

};


