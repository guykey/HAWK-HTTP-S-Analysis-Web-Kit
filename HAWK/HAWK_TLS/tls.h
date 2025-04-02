#pragma once
#include "TlsRecords.h"


class TLS
{
public:
	TLS(const std::string& dstServer, const std::string& port, bool isServer=false);
	TLS(Communicator* com, bool isServer=false); // c'tor for setting client with an exsiting communicator
	TLS(const std::string& dstServer, Communicator* com);

	~TLS();

	void do_handshake();

	

	bool send(const std::string& data);
	bytes recv();

	bool sendHttpGet();

	bool Connected();
	

protected:
	// I don't think we need those c'tors
	TLS(const std::string& port);
	TLS(const std::string& port, SOCKET serverSocket);

	bool _connected = false;


	bool _server;
	Communicator* _dstCom;
	std::string _dst;
	std::string _port;
	

	CipherSuite _cipherSuite;
	word _cipherSuiteCode;

	bytes _clientSessionId;
	bytes _serverSessionId;

	bytes _clientRandom;
	bytes _serverRandom;

	bytes _otherPublicKey;

	bytes _masterSecret;

	std::vector<TLSRecord*> _requests; // vector that holds all the requests objects. When needed, you iterate the
	// vector and call toBytes for each request

	std::vector <Certificate*> _certs;
	bool sendClientHello();
	bool recvServerHello();
	bool recvCertificates();
	bool recvServerKeyExchange();
	bool recvServerHelloDone();
	bool sendClientKeyExchange();
	bool sendChangeCipherSpec();
	bool recvChangeCipherSpec();
	bool sendClientEncryptedMessage();
	bool recvServerEncryptedMessage();
};
