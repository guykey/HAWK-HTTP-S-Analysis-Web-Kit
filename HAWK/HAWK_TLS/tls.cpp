#include "tls.h"
#include <vector>
#include <random>
#include <algorithm>
#include <fstream>

//initialize tls
TLS::TLS(const std::string& dst, const std::string& port, bool isServer) : _cipherSuite(isServer), _cipherSuiteCode(0)
{
	this->_dst = dst;
	this->_port = port; //set tls connection values
    this->_server = isServer;

	//this->_dstCom = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); //create socket
    this->_dstCom = new SocketCommunicator();
}

TLS::TLS(Communicator* com, bool isServer) : _cipherSuite(isServer), _cipherSuiteCode(0)
{
    this->_server = isServer;
    this->_dstCom = com;
}

TLS::TLS(const std::string& dstServer, Communicator* com) : _cipherSuite(false), _cipherSuiteCode(0)
{
    this->_server = false;
    this->_dstCom = com;
    this->_dst = dstServer;
}

TLS::~TLS()
{
    int i = 0;

    for (i = 0; i < _requests.size(); i++)
    {
        delete _requests[i];
    }
    
    for (i = 0; i < _certs.size(); i++)
    {
        delete _certs[i];
    }
    //delete this->_dstCom;
}

TLS::TLS(const std::string& port) : _cipherSuite(true), _cipherSuiteCode(0)
{
    
    this->_port = port;
    this->_server = true;
    this->_dst = "NONE";//will change in the client hello, when we get the sni

    this->_dstCom = new SocketCommunicator();
}

//the tls server might need to get the socket when its already connected, so we make a ctor that gets a socket too
TLS::TLS(const std::string &port, SOCKET serverSocket) : _cipherSuite(true), _cipherSuiteCode(0)
{
    this->_port = port;
    this->_server = true;
    this->_dst = "NONE";

    this->_dstCom = new SocketCommunicator(serverSocket);
}

void TLS::do_handshake()
{
    if(_server)
        throw std::exception("Can't Call do_handshake For Server Instance!");

    // acctual handshake
    //unsafe, need to make sure this is fine
    //std::cout << __FUNCTION__ " - JUST FOR TESTING TLS CLIENT!!!, REMOVE IF RUNNING MITM" << std::endl;
    //((SocketCommunicator*)(this->_dstCom))->connect(this->_dst, this->_port);
    
    //std::cout << "Performing handshake\n";
    // client
    sendClientHello();


    recvServerHello();


    _cipherSuite.ComputeCipherSuite(_cipherSuiteCode);

    recvCertificates();

    recvServerKeyExchange();

    recvServerHelloDone();

    _masterSecret = _cipherSuite.KeyExchange(_otherPublicKey, _clientRandom, _serverRandom);


    sendClientKeyExchange();

    sendChangeCipherSpec();

    sendClientEncryptedMessage();


    recvChangeCipherSpec();

    recvServerEncryptedMessage();

    //std::cout << "handshake done\n\n\n";
    this->_connected = true;
}

bool TLS::send(const std::string& data)
{
    bytes message = _cipherSuite.getSymetric()->encrypt(data, TLS_APPLICATION_DATA);
    
    return TLSRecord::send(this->_dstCom, message, TLS_APPLICATION_DATA);
}

bytes TLS::recv()
{
    bytes response;
    TLSRecord::recvPacket(_dstCom, response);
    bytes decrypted = this->_cipherSuite.getSymetric()->decrypt(response, TLS_APPLICATION_DATA);

    return decrypted;
}

bool TLS::sendHttpGet()
{
    bytes httpRequest = "GET / HTTP/1.1\r\nHost: " + this->_dst + "\r\nConnection: close\r\n\r\n";
    
    return send(httpRequest);
}

bool TLS::Connected()
{
    return this->_connected;
}



bool TLS::sendClientHello()
{    
    generateRandom(_clientRandom, RANDOM_STREAM_SIZE);
    generateRandom(_clientSessionId, RANDOM_STREAM_SIZE);

    ClientHello* clientHello = new ClientHello(_clientRandom, _clientSessionId, _dst);
    _requests.push_back(clientHello);

    return clientHello->send(_dstCom);
}





bool TLS::recvServerHello()
{
    bytes content;
    TLSRecord::recvPacket(_dstCom, content);

    size_t offset = 0;

    byte handshakeType = content[offset++];
    offset += CONTENT_LENGTH_SIZE; // length

    word version2 = (word)bytesToInt(content, offset, offset + sizeof(word));
    offset += sizeof(word);

    _serverRandom.push(content.slice(offset, offset + RANDOM_STREAM_SIZE));
    offset += RANDOM_STREAM_SIZE;

    byte sessionIdLength = content[offset++];
    _serverSessionId.push(content.slice(offset, offset + sessionIdLength));
    offset += sessionIdLength;

    _cipherSuiteCode = (word)bytesToInt(content, offset, offset + sizeof(word));
    offset += sizeof(word);

    byte compressionMethod = content[offset++];
    word extensionsLength = (word)bytesToInt(content, offset, offset + sizeof(word));
    offset += sizeof(word);

    size_t extensionsBytesRead = 0;
    std::vector<extension> extensions;

    while (extensionsBytesRead < extensionsLength)
    {
        extension current;
        current.type = (word)bytesToInt(content, offset, offset + sizeof(word));
        offset += sizeof(word);

        current.extensionLength = (word)bytesToInt(content, offset, offset + sizeof(word));
        offset += sizeof(word);

        extensionsBytesRead += 2 * sizeof(word) + current.extensionLength;

        if (current.extensionLength <= 0)
        {
            extensions.push_back(current);
            continue;
        }

        bytes data = content.slice(offset, offset + current.extensionLength);

        current.data.push(data);

        offset += current.extensionLength;

        extensions.push_back(current);
    }

    _requests.push_back(new ServerHello(_serverRandom, _serverSessionId, _cipherSuiteCode, extensions));

	return true;
}


bool TLS::recvCertificates()
{
    bytes content;
    TLSRecord::recvPacket(_dstCom, content);

    size_t offset = 0;

    byte handshakeType = content[offset++];
    offset += CONTENT_LENGTH_SIZE; // length


    size_t certTotalLength = bytesToInt(content, offset, offset + CONTENT_LENGTH_SIZE);
    offset += CONTENT_LENGTH_SIZE;

    size_t bytesRead = 0;
    size_t certLength = 0;

    bytes cert;

    while (bytesRead <= certTotalLength)
    {
        certLength = (size_t)bytesToInt(content, offset, offset + CONTENT_LENGTH_SIZE);
        bytesRead += certLength;

        offset += CONTENT_LENGTH_SIZE;

        if (certLength <= 0)
            break;

        cert = content.slice(offset, offset + certLength);
        _certs.push_back(new Certificate(cert));

        offset += certLength;
    }

    _requests.push_back(new CertificateRequest(_certs));

    if (verifyChainOfTrust(_certs, _dst))
    {
        std::cout << "Chain Of Trust is OK\n";
    }
    else
    {
        std::cout << "WARNING: Chain of trust isn't verified\n";
    }

    return true;
}



bool TLS::recvServerKeyExchange()
{
    bytes content;
    TLSRecord::recvPacket(_dstCom, content);

    size_t offset = 0;

    // only for ecdhe!

    byte handshakeType = content[offset++];
    offset += CONTENT_LENGTH_SIZE; // length

    byte curveType = content[offset++];

    word namedCurve = (word)bytesToInt(content, offset, offset + sizeof(word));
    offset += sizeof(word);

    byte pubKeyLen = content[offset++];
    _otherPublicKey = content.slice(offset, offset + pubKeyLen);

    offset += pubKeyLen;

    word signatureAlgo = (word)bytesToInt(content, offset, offset + sizeof(word));
    offset += sizeof(word);

    word signatureLength = (word)bytesToInt(content, offset, offset + sizeof(word));


    offset += sizeof(word);

    bytes serverSignature = content.slice(offset, offset + signatureLength);
    
    _requests.push_back(new ServerKeyExchange(_otherPublicKey, serverSignature, signatureAlgo, curveType, namedCurve));

    bytes signedData(_otherPublicKey);
    signedData.push((byte)pubKeyLen);
    signedData.push(namedCurve, sizeof(word));
    signedData.push((byte)curveType);
    signedData.push(this->_serverRandom);
    signedData.push(this->_clientRandom);

    HashFunction* hash;
    signatureAlgo >>= 8;

    switch (signatureAlgo)
    {
    case SHA1:
        hash = sha1::getInstance();
        break;

    case SHA224:
        hash = sha224::getInstance();
        break;

    case SHA256:
        hash = sha256::getInstance();
        break;

    case SHA384:
        hash = sha384::getInstance();
        break;

    case SHA512:
        hash = sha512::getInstance();
        break;

    default:
        std::cout << "Unable to identify signature algorithm. Didn't verify server signature";
        return true;
    }

    if (_certs[0]->verifySignature(signedData, serverSignature, hash))
    {
        std::cout << "Server signature OK :)\n";
    }
    else
    {
        std::cout << "WARNING: Server signature isn't verified\n";
    }


    return true;
}



bool TLS::recvServerHelloDone()
{
    bytes content;
    TLSRecord::recvPacket(_dstCom, content); // no content

    _requests.push_back(new ServerHelloDone()); // it needs to be pointy

    return true;
}


bool TLS::sendClientKeyExchange()
{
    bytes pubkey;

    ClientKeyExchange* request = new ClientKeyExchange(_cipherSuite.getAsymetric()->getRawPublicKey());
    _requests.push_back(request);

    return request->send(_dstCom);
}




bool TLS::sendChangeCipherSpec()
{
    ChangeCipherSpec request;

    return request.send(_dstCom, CHANGE_CIPHER_SPEC); // different type, not handshake type
}

bool TLS::recvChangeCipherSpec()
{
    bytes content;
    TLSRecord::recvPacket(_dstCom, content); // no content...

    return true;
}


bool TLS::sendClientEncryptedMessage()
{
    bytes allTraffic;
    bytes req;

    for (auto request : _requests)
    {
        req = request->toBytes();
        allTraffic.concat(req);
    }

    bytes hashOfAllTraffic = _cipherSuite.getHash()->compute(allTraffic);
    bytes verifyData = prf_sha<CryptoPP::SHA256>(_masterSecret, "client finished", hashOfAllTraffic, VERIFY_DATA_LENGTH_AES_GCM_128);

    bytes header;
    header.push(0x0c);
    header.push(0, sizeof(word));
    header.push(0x14);

    verifyData.push(header);

    bytes message = _cipherSuite.getSymetric()->encrypt(verifyData, TLS_HANDSHAKE);

    EncryptedHandshakeMessage* clientMessage = new EncryptedHandshakeMessage(message);

    _requests.push_back(clientMessage);

    return clientMessage->send(_dstCom);
}



bool TLS::recvServerEncryptedMessage()
{
    bytes content;
    TLSRecord::recvPacket(_dstCom, content);

    bytes decrypted = this->_cipherSuite.getSymetric()->decrypt(content, TLS_HANDSHAKE);

    return true;
}
