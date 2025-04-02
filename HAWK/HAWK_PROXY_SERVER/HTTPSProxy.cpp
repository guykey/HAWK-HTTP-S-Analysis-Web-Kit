#include "HTTPSProxy.h"


HTTPRequest Connection::recvHttp(SocketCommunicator& com)
{
	const size_t buffer_size = RECV_SIZE;
	bytes buffer(buffer_size);
	bytes request;
	int bytesReceived = 0;

	while ((bytesReceived = com.recvBuff(buffer)) > 0) {
		request += buffer;
		size_t bufferSize = buffer.size();
		buffer.clear();
		size_t headerEnd = request.find("\r\n\r\n");
		if (headerEnd != std::string::npos) {

			size_t contentLengthPos = request.find("Content-Length: ");
			if (contentLengthPos != std::string::npos) {
				size_t lineEnd = request.find("\r\n", contentLengthPos);
				int contentLength = std::stoi(request.substr(contentLengthPos + 16, lineEnd - contentLengthPos - 16));

				if (request.length() >= headerEnd + 4 + contentLength) {
					break;
				}
			}
		}
		if (bufferSize < buffer_size)
			break;
	}
	if (request.empty())
		throw std::exception("Socket Closed");

	return HTTPRequest(request);
}

// gets reference because this could either be TLS (client) or TLSServer (server)
HTTPRequest HTTPSMITMCon::recvHttps(TLS& con)
{
	bytes buffer;
	bytes request;

	while (true) {
		buffer = con.recv();
		request += buffer;

		size_t headerEnd = request.find("\r\n\r\n");
		if (headerEnd != std::string::npos) {
			// Identify the request method
			std::string requestLine = request.substr(0, request.find("\r\n"));
			bool isPostOrPut = (requestLine.find("POST") == 0 || requestLine.find("PUT") == 0);

			// Check for Content-Length
			size_t contentLengthPos = request.find("Content-Length: ");
			if (contentLengthPos != std::string::npos) {
				size_t lineEnd = request.find("\r\n", contentLengthPos);
				int contentLength = std::stoi(request.substr(contentLengthPos + 16, lineEnd - contentLengthPos - 16));
				while (request.length() < headerEnd + 4 + contentLength) {
					buffer = con.recv();
					request += buffer;
				}
				break;
			}

			// Check for Transfer-Encoding: chunked
			size_t chunkedPos = request.find("Transfer-Encoding: chunked");
			if (chunkedPos != std::string::npos) {
				size_t bodyStart = headerEnd + 4;
				while (true) {
					size_t chunkSizeEnd = request.find("\r\n", bodyStart);
					while (chunkSizeEnd == std::string::npos) {
						buffer = con.recv();
						request += buffer;
						chunkSizeEnd = request.find("\r\n", bodyStart);
					}

					int chunkSize = std::stoi(request.substr(bodyStart, chunkSizeEnd - bodyStart), nullptr, 16);
					if (chunkSize == 0) {
						break; // End of chunked transfer
					}

					bodyStart = chunkSizeEnd + 2 + chunkSize + 2;
					while (request.length() < bodyStart) {
						buffer = con.recv();
						request += buffer;
					}
				}
				break;
			}
			// If it's a GET, HEAD, DELETE, etc., the request ends at the headers
			if (!isPostOrPut) {
				break;
			}
		}
	}
	return HTTPRequest(request);
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



HTTPSProxyServer::HTTPSProxyServer(Port port) : _listenSock(std::to_string(port)), _intercept(false)
{
}

void HTTPSProxyServer::proxy(int proxyType)
{
	//IF USING WINDIVERT
	//there is no http Connect, so we need to somehow figure our the dst server (host name) (maybe use sni)
	switch (proxyType)
	{
	case HTTPS_PROXY:
		this->_registry.setHTTPSProxy();
		break;
	case HTTP_PROXY:
		this->_registry.setHTTPProxy();
		break;
	case HTTP_PROXY | HTTPS_PROXY:
		this->_registry.setProxy();
		break;
	default:
		throw std::exception(__FUNCTION__  "- Invalid value for \"proxyType\"");
	}

	while (true)
	{
		SOCKET newClient = this->_listenSock.accept();

		bytes initialRequestBuff(RECV_SIZE);
		//just peek the data, not read, to know type of connection
		int bytesRead = ::recv(newClient, (char*)initialRequestBuff.data(), (int)(initialRequestBuff.size()), MSG_PEEK);
		if (0 > bytesRead)
			continue;
		HTTPRequest initialRequest(initialRequestBuff);
		Connection* pCon = nullptr;



		if (initialRequest.getMethod() == "CONNECT")
		{
			if (std::find(this->_tunnelAddresses.begin(), this->_tunnelAddresses.end(), initialRequest.getHost()) != this->_tunnelAddresses.end())
			{
				//is in tunnel addresses
				//for now is the whitelist

				std::cout << "   Connecting to (TLS MITM) " << initialRequest.getHost() << std::endl;
				pCon = new HTTPSMITMCon(newClient);
			}
			else
			{
				std::cout << "   Tunneling to " << initialRequest.getHost() << std::endl;
				pCon = new HTTPSTunnelCon(newClient);
			}
		}
		else
		{
			std::cout << "   Connecting to (HTTP MITM) " << initialRequest.getHost() << std::endl;
			pCon = new HTTPCon(newClient);

		}
		this->_connections.insert(pCon);
		try
		{
			std::thread clientThread(&Connection::proxy, pCon);//WTF
			clientThread.detach();
		}
		catch (const std::exception& e)
		{
			std::cerr << e.what() << std::endl;
		}
	}
}

void HTTPSProxyServer::toggleIntercept()
{
}

void HTTPSProxyServer::stop()
{
	this->_registry.revertChanges();
}

bool HTTPSProxyServer::intercept()
{
	return false;
}

HTTPSProxyServer::~HTTPSProxyServer()
{
	this->_registry.revertChanges();
}

Connection::Connection(SOCKET clientConnection) : _clientCon(clientConnection)
{
}

Connection::~Connection() = default;



HTTPCon::HTTPCon(SOCKET clientConnection) : Connection(clientConnection)
{
}

void HTTPCon::proxy()
{
	try
	{
		SOCKET clientFd = this->_clientCon.getFD();
		SOCKET serverFd = this->_serverCon.getFD();
		fd_set read_fds;

		bytes initialRequestBuff(RECV_SIZE);
		//just peek the data, not read, to know type of connection
		int bytesRead = ::recv(clientFd, (char*)initialRequestBuff.data(), (int)(initialRequestBuff.size()), MSG_PEEK);
		if (0 > bytesRead)
			throw std::exception("Socket Closed!");
		HTTPRequest initialRequest(initialRequestBuff);


		this->_serverCon.connect(initialRequest.getHost(), std::to_string(HTTP_PORT));



		while (true)
		{
			FD_ZERO(&read_fds);
			FD_SET(clientFd, &read_fds);
			FD_SET(serverFd, &read_fds);

			int max_fd = (int)(max(clientFd, serverFd) + 1);

			if (select(max_fd, &read_fds, NULL, NULL, NULL) == SOCKET_ERROR) {
				std::cerr << "select() failed\n";
				break;
			}

			if (FD_ISSET(clientFd, &read_fds)) {
				HTTPRequest request = Connection::recvHttp(this->_clientCon);
				this->_serverCon.send(request.getRaw(), request.getRaw().size());
			}

			if (FD_ISSET(serverFd, &read_fds)) {
				HTTPRequest response = Connection::recvHttp(this->_serverCon);
				this->_clientCon.send(response.getRaw(), response.getRaw().size());
			}


		}
	}
	catch (const std::exception& e)
	{
		std::cout << e.what() << std::endl;
	}

}

HTTPSMITMCon::HTTPSMITMCon(SOCKET clientConnection) : Connection(clientConnection)
{
	this->_tlsClient = nullptr;
	this->_tlsServer = nullptr;

	HTTPRequest initialRequest = Connection::recvHttp(this->_clientCon);//should be CONNECT
	const std::string host = initialRequest.getHost();

	this->_serverCon.connect(host, std::to_string(HTTPS_PORT));

	const bytes okMsg("HTTP/1.1 200 Connection Established\r\n\r\n");
	this->_clientCon.send(okMsg, okMsg.size());

	try
	{
		//currently, no runtime certificate generation
		this->_tlsServer = new TLSServer("guthib.com_cert.der", "guthib.com_key.pem", &(this->_clientCon));

		this->_tlsServer->listen();

		this->_tlsClient = new TLS(host, &(this->_serverCon));
		this->_tlsClient->do_handshake();
	}
	catch (const std::exception& e)
	{
		//if failed to connect to client
		//we send a simple error page, super cool
		if (this->_tlsServer->Connected() && !(this->_tlsClient->Connected()))
		{
			//recv client request
			this->_tlsServer->recv();
			this->_tlsServer->send(HawkErrorPage);
		}
		std::cout << e.what() << std::endl;
	}


}

HTTPSMITMCon::~HTTPSMITMCon()
{
	delete this->_tlsClient;
	delete this->_tlsServer;
}

void HTTPSMITMCon::proxy()
{
	try
	{
		auto clientFd = this->_clientCon.getFD();
		fd_set read_fds;
		auto serverFd = this->_serverCon.getFD();


		while (true)
		{
			FD_ZERO(&read_fds);
			FD_SET(clientFd, &read_fds);
			FD_SET(serverFd, &read_fds);

			int max_fd = (int)(max(clientFd, serverFd) + 1);

			if (select(max_fd, &read_fds, NULL, NULL, NULL) == SOCKET_ERROR) {
				std::cerr << "select() failed\n";
				break;
			}

			if (FD_ISSET(clientFd, &read_fds)) {
				HTTPRequest request = this->recvHttps(*(this->_tlsServer));
				std::cout << request << std::endl;
				this->_tlsClient->send(request.getRaw());
			}

			if (FD_ISSET(serverFd, &read_fds)) {
				HTTPRequest response = this->recvHttps(*(this->_tlsClient));
				std::cout << response << std::endl;
				this->_tlsServer->send(response.getRaw());
				//this->_clientCon.send(response.getRaw(), response.getRaw().size());
			}


		}
	}
	catch (const std::exception& e)
	{


		std::cout << e.what() << std::endl;
	}
}

HTTPSTunnelCon::HTTPSTunnelCon(SOCKET clientConnection) : Connection(clientConnection)
{
}

HTTPSTunnelCon::~HTTPSTunnelCon() = default;

void HTTPSTunnelCon::proxy()
{
	try
	{
		auto clientFd = this->_clientCon.getFD();
		fd_set read_fds;

		HTTPRequest initialRequest = Connection::recvHttp(this->_clientCon);//should be connect request
		const std::string host = initialRequest.getHost();

		this->_serverCon.connect(host, std::to_string(HTTPS_PORT));
		auto serverFd = this->_serverCon.getFD();

		const bytes okMsg("HTTP/1.1 200 Connection Established\r\n\r\n");
		this->_clientCon.send(okMsg, okMsg.size());

		while (true)//purely tunneling, the data being transferred here is the tls session between chrome and the dst server
		{//we cant see it because we don't have the keys for this conversation
			FD_ZERO(&read_fds);
			FD_SET(clientFd, &read_fds);
			FD_SET(serverFd, &read_fds);

			int max_fd = (int)(max(clientFd, serverFd) + 1);

			if (select(max_fd, &read_fds, NULL, NULL, NULL) == SOCKET_ERROR) {
				std::cerr << "select() failed\n";
				break;
			}

			if (FD_ISSET(clientFd, &read_fds)) {
				bytes request;
				this->_clientCon.recv(request, RECV_SIZE);
				this->_serverCon.send(request, request.size());
			}

			if (FD_ISSET(serverFd, &read_fds)) {
				bytes response;
				this->_serverCon.recv(response, RECV_SIZE);
				this->_clientCon.send(response, response.size());
			}


		}
	}
	catch (const std::exception& e)
	{
		std::cout << e.what() << std::endl;
	}
}
