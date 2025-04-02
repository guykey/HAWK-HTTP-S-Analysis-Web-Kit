#pragma once

#include <iostream>
#include <unordered_set>
#include <thread>
#include <mutex>

#include <deque>

#include "WSA.h"
#include "../HAWK_TLS/tlsServer.h"
#include "../HAWK_TLS/Communicator.h"
#include "RegistryWriter.h"
#include "HTTP.h"


#include "HawkErrorPage.h"

#define RECV_SIZE 4096



#define SERVER_LISTEN 8582

#define HTTP_PORT 80
#define HTTPS_PORT 443

#define HTTP_PROXY 0x2
#define HTTPS_PROXY 0x1

typedef unsigned short Port;


class Connection;
class HTTPSProxyServer
{
public:
	HTTPSProxyServer(Port port=SERVER_LISTEN);

	void proxy(int proxyType=HTTPS_PROXY);
	void toggleIntercept();

	void stop();

	bool intercept();

	~HTTPSProxyServer();

protected:
	RegistryWriter _registry;
	SocketCommunicator _listenSock;

	//std::deque<HTTPRequest> _blockedQueue;
	std::mutex _connectionsLock;
	std::unordered_set<Connection*> _connections;

	bool _intercept;


	const std::unordered_set<std::string> _tunnelAddresses = {
		"guthib.com"
	};


};


class Connection
{
public:
	Connection(SOCKET clientConnection);
	virtual ~Connection();
	virtual void proxy()=0;
	static HTTPRequest recvHttp(SocketCommunicator& com);
protected:
	SocketCommunicator _clientCon;
	SocketCommunicator _serverCon;

	std::vector<HTTPRequest> _requests;
};

class HTTPCon : public Connection
{
public:
	HTTPCon(SOCKET clientConnection);
	virtual void proxy() override;
protected:

};

class HTTPSMITMCon : public Connection
{
public:
	HTTPSMITMCon(SOCKET clientConnection);
	~HTTPSMITMCon();
	virtual void proxy() override;

	static HTTPRequest recvHttps(TLS& con);
protected:
	
	TLS* _tlsClient;
	TLSServer* _tlsServer;
};

class HTTPSTunnelCon : public Connection
{
public:
	HTTPSTunnelCon(SOCKET clientConnection);
	~HTTPSTunnelCon();
	virtual void proxy() override;
protected:
};



