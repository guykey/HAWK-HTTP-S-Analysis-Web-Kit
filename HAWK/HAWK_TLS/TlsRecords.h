#include "constants.hpp"
#include "CipherSuite.h"
#include "Certificate.h"
#include "Communicator.h"


struct extension // an extension
{
	word type;
	word extensionLength;
	bytes data;
};


//parent class for all tls Record requests/responses
class TLSRecord
{
public:
	TLSRecord() { };

	virtual const bytes toBytes() = 0;

	bool send(Communicator& com, byte type= TLS_HANDSHAKE);

	static bool send(Communicator& com, const bytes& data, byte type = TLS_APPLICATION_DATA);
	static void recvPacket(Communicator& com, bytes& buffer);

	static void peekPacket(SocketCommunicator& com, bytes& buffer);

	virtual std::string getRecord() = 0;


	//inline bool send(Communicator* com, byte type = TLS_HANDSHAKE);

	//inline static bool send(Communicator* com, const bytes& data, byte type = TLS_APPLICATION_DATA);
	//inline static void recvPacket(Communicator* com, bytes& buffer);

	bool send(Communicator* com, byte type = TLS_HANDSHAKE)
	{
		return TLSRecord::send(*com, type);
	}

	static bool send(Communicator* com, const bytes& data, byte type = TLS_APPLICATION_DATA)
	{
		return TLSRecord::send(*com, data, type);
	}

	static void recvPacket(Communicator* com, bytes& buffer)
	{
		TLSRecord::recvPacket(*com, buffer);
	}
	
	static void peekPacket(SocketCommunicator* com, bytes& buffer)
	{
		TLSRecord::peekPacket(*com, buffer);
	}


protected:
};


class ClientHello : public TLSRecord
{
public:
	ClientHello(const bytes& random, const bytes& sessionId, const std::string& dstUrl, const bytes& cipherSuites = CipherSuite::getSupportedCipherSuites()) : _random(random), _sessionId(sessionId), _dst(dstUrl), _cipherSuites(cipherSuites) {}
	ClientHello(const bytes& random, const bytes& sessionId, const std::string& dstUrl, const std::vector<extension>& extensions, const bytes& cipherSuites=CipherSuite::getSupportedCipherSuites()) : _random(random), _sessionId(sessionId), _dst(dstUrl), _extensions(extensions), _cipherSuites(cipherSuites) {}
	virtual const bytes toBytes() override;

	const bytes getRandom() const { return _random; }
	const bytes getSessionId() const { return _sessionId; }
	const std::string getDst() const { return _dst; }

	virtual std::string getRecord() {
		return std::string("Client Hello");
	}

private:
	bytes _random;
	bytes _sessionId;
	bytes _cipherSuites;
	std::string _dst;
	std::vector<extension> _extensions;
};


class ServerHello : public TLSRecord
{
public:
	ServerHello(const bytes& random, const bytes& sessionId, word cipherSuite, const std::vector<extension>& extensions) : _random(random), _sessionId(sessionId), _cipherSuite(cipherSuite), _extensions(extensions) {}
	virtual const bytes toBytes() override;

	const bytes getRandom() const { return _random; }
	const bytes getSessionId() const { return _sessionId; }
	word getCipherSuite() const { return (_cipherSuite); }
	const std::vector<extension> getExtensions() const { return _extensions; }

	virtual std::string getRecord() {
		return std::string("Server Hello");
	}
	
private:
	bytes _random;
	bytes _sessionId;
	word _cipherSuite;
	std::vector<extension> _extensions;
};


class CertificateRequest : public TLSRecord
{
public:
	CertificateRequest(const std::vector<Certificate*> certs) : _certs(certs) {}
	virtual const bytes toBytes() override;

	std::vector<Certificate*> getCerts() const { return _certs; }

	virtual std::string getRecord() {
		return std::string("Certficate");
	}
private:
	std::vector<Certificate*> _certs;
};


class ServerKeyExchange : public TLSRecord
{
public:
	ServerKeyExchange(const bytes& pubKey, const bytes& signature, word signatureAlgo, byte curveType, word namedCurve) : _pubKey(pubKey), _signature(signature), _signatureAlgo(signatureAlgo), _curveType(curveType), _namedCurve(namedCurve) {}
	virtual const bytes toBytes() override;

	bytes getPubKey() const { return _pubKey; }
	bytes getSignature() const { return _signature; }
	virtual std::string getRecord() {
		return std::string("Server Key Exchange");
	}
private:
	bytes _pubKey;
	bytes _signature;
	word _signatureAlgo;

	byte _curveType;
	word _namedCurve;
};


class ServerHelloDone : public TLSRecord
{
public:
	ServerHelloDone() {}
	virtual const bytes toBytes() override;
	virtual std::string getRecord() {
		return std::string("Server Hello Done");
	}
};


class ClientKeyExchange : public TLSRecord
{
public:
	ClientKeyExchange(const bytes& pubKey) : _pubKey(pubKey) {}
	virtual const bytes toBytes() override;

	virtual std::string getRecord() {
		return std::string("Client Key Exchange");
	}

private:
	bytes _pubKey;
};


class ChangeCipherSpec : public TLSRecord
{
public:
	ChangeCipherSpec() {}
	virtual const bytes toBytes() override
	{
		bytes content;
		content.push(CHANGE_CIPHER_SPEC_CONTENT);
		return content;
	}	
	virtual std::string getRecord() {
		return std::string("Change Cipher Spec");
	}
};


class EncryptedHandshakeMessage : public TLSRecord
{
public:	
	EncryptedHandshakeMessage(const bytes& message) : _message(message) {}// gets the encrypted message
	virtual const bytes toBytes() override;

	virtual std::string getRecord() {
		return std::string("Encrypted Handshake Message");
	}
private:
	bytes _message;
};
