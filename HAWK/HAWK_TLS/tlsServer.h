#pragma once
#include "tls.h"



class TLSServer : public TLS
{
public:
	TLSServer(const std::string& certPath, const std::string& keyPath, const std::string& port);
	TLSServer(Communicator* com);
	~TLSServer();


	static std::string getSniFromPeekClientHello(SocketCommunicator* com);

	TLSServer(const std::string &certPath, const std::string &keyPath, const std::string& port, SOCKET connectedSocket);
	TLSServer(const std::string& certPath, const std::string& keyPath, Communicator* com);
	//ctor for divertor
	//TLSServer(const std::string& certPath, const std::string& keyPath);
	//need to add ctor for general Communicator device

	void listen();


protected:

	SocketCommunicator _listeningSock; // only for debug

	Certificate* _serverCertificate = nullptr;
	CertificatePrivateKey* _serverCertPrivateKey = nullptr;

	bytes _signature;

	void do_handshake() = delete;//make it so it can't be called as server
	bool sendHttpGet() = delete;//that too

	void generateSignature();
	


	bool recvClientHello();

	bool sendServerHello();

	bool sendCertificates();

	bool sendServerKeyExchange();

	bool sendServerHelloDone();

	bool recvClientKeyExchange();

	bool recvClientEncryptedMessage();

	bool sendServerEncryptedMessage();


};
