#include "tlsServer.h"
#include "integer.h"
#include "cryptlib.h"

TLSServer::TLSServer(const std::string& certPath, const std::string& keyPath, const std::string& port) : TLS(port), _listeningSock(port)
{

    this->_serverCertificate = new Certificate(certPath, true);//use path constructor
    std::cout << "Certificate loaded successfully!" << std::endl;

    this->_serverCertPrivateKey = new CertificatePrivateKey(keyPath, true);
    std::cout << "Private key loaded successfully!" << std::endl;
    //now need to get the private key initialized
}

TLSServer::TLSServer(Communicator* com) : TLS(com, true)
{
}

TLSServer::~TLSServer()
{
	if (this->_serverCertificate)
		delete this->_serverCertificate;

    if (this->_serverCertPrivateKey)
        delete this->_serverCertPrivateKey;

    
}


std::string TLSServer::getSniFromPeekClientHello(SocketCommunicator* com)
{
    std::string dst = "";
    bytes content;
    TLSRecord::peekPacket(com, content);
    size_t offset = 0;
    bytes dstServer;

    byte handshakeType = content[offset++];//handshake type
    offset += CONTENT_LENGTH_SIZE; // length
    word version = (word)bytesToInt(content, offset, offset + sizeof(word));//tls version
    offset += sizeof(word);
    offset += RANDOM_STREAM_SIZE;


    byte sessionIdLength = content[offset++];//length of session id
    offset += sessionIdLength;
    word cipherSuitesLength = (word)bytesToInt(content, offset, offset + sizeof(word));//size of cipher suites
    offset += sizeof(word);
    bytes cipherSuites = content.slice(offset, offset + cipherSuitesLength);//cipher suites supported
    offset += cipherSuitesLength;
    word compressionTypeLength = content[offset++];//length of compression type
    bytes compressionType = content.slice(offset, offset + compressionTypeLength);//compression type
    offset += compressionTypeLength;
    const word extensionsLength = (word)bytesToInt(content, offset, offset + sizeof(word));//length of extensions
    offset += sizeof(word);
    size_t extensionBytesRead = 0;//bytes of extensions read, and list of the extensions

    std::vector<extension> extensions;//read all extensions
    while (extensionBytesRead < extensionsLength)
    {
        extension current;
        current.type = (word)bytesToInt(content, offset, offset + sizeof(word));//get the type
        offset += sizeof(word);
        extensionBytesRead += sizeof(word);

        current.extensionLength = (word)bytesToInt(content, offset, offset + sizeof(word));//get the length

        offset += sizeof(word);
        extensionBytesRead += sizeof(word);

        if (current.extensionLength > 0)//if length is greater than 0
        {
            current.data.push(content.slice(offset, offset + current.extensionLength));//get the data
            offset += current.extensionLength;
            extensionBytesRead += current.extensionLength;
            //extract the dstUrl if it is sni
            if (current.type == SERVER_NAME_INDEX_EXTENSION_TYPE && dstServer == "")
            {
                size_t sniOffset = 0;
                word sniLength = (word)bytesToInt(current.data, sniOffset, sniOffset + sizeof(word));
                sniOffset += sizeof(word);
                byte sniType = current.data[sniOffset++];
                word urlLength = (word)bytesToInt(current.data, sniOffset, sniOffset + sizeof(word));
                sniOffset += sizeof(word);

                dstServer.push(current.data.slice(sniOffset, sniOffset + urlLength));
                sniOffset += urlLength;

                dst = dstServer;
                break;
            }
        }
        extensions.push_back(current);//push into list
    }

    return dst;
}

//The proxy server will either get a connection from the client, or windivert will give us socket like action
//in both cases we need a ctor that will get the socket to the client, so this is it                                              call the correct ctor
TLSServer::TLSServer(const std::string &certPath, const std::string &keyPath, const std::string& port, SOCKET connectedSocket) : TLS(port, connectedSocket)
{
    this->_serverCertificate = new Certificate(certPath, true);//use path constructor
    std::cout << "Certificate loaded successfully!" << std::endl;

    this->_serverCertPrivateKey = new CertificatePrivateKey(keyPath, true);//WORKS, get the n and d values from pem!
    std::cout << "Private key loaded successfully!" << std::endl;
}

TLSServer::TLSServer(const std::string& certPath, const std::string& keyPath, Communicator* com) : TLS(com, true)
{

    this->_serverCertificate = new Certificate(certPath, true);//use path constructor
    //std::cout << "Certificate loaded successfully!" << std::endl;

    this->_serverCertPrivateKey = new CertificatePrivateKey(keyPath, true);//WORKS, get the n and d values from pem!
    //std::cout << "Private key loaded successfully!" << std::endl;
}

void TLSServer::listen()
{
    
    if (_dstCom->getType() == SOCKET_COM && false)
    {
        std::cout << "MAKING NEW SOCKET!!, REMOVE FOR PROXY SERVER, THIS IS FOR CHECKING TLS SERVER BY ITSELF" << std::endl;
        SOCKET newSocket = _listeningSock.accept();
        if (newSocket == INVALID_SOCKET)
            throw std::exception("Error Creating Socket With Client!");

        delete _dstCom;//delete previous communicator
        //make new socket communicator
        this->_dstCom = new SocketCommunicator(newSocket);
    }
    
    _cipherSuite.ComputeCipherSuite(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    generateRandom(this->_serverRandom, RANDOM_STREAM_SIZE);

    //std::cout << "Begining Handshake\n";
    

    recvClientHello();
    //std::cout << "Recv ClientHello" << std::endl;

    sendServerHello();
    //std::cout << "Sent ServerHello" << std::endl;

    sendCertificates();
    //std::cout << "Sent Certificates" << std::endl;

    sendServerKeyExchange();
    //std::cout << "Sent ServerKeyExchange" << std::endl;

    sendServerHelloDone();
    //std::cout << "Sent ServerHelloDone" << std::endl;

    recvClientKeyExchange();
    //std::cout << "Recv ClientKeyExchange" << std::endl;

    recvChangeCipherSpec();
    //std::cout << "Recv ChangeCipherSpec" << std::endl;

    //std::cout << "Recv ClientEncryptedMessage" << std::endl;
    if (recvClientEncryptedMessage())
        ;//std::cout << "    Client Message OK\n";
    else
        ;//std::cout << "    Client Message not OK\n";

    sendChangeCipherSpec();
    //std::cout << "Sent ChangeCipherSpec" << std::endl;

    sendServerEncryptedMessage();
    //std::cout << "Sent ServerEncryptedMessage" << std::endl;

    //recvClientRequest();
    this->_connected = true;
}

void TLSServer::generateSignature()
{
    bytes signatureData(this->_cipherSuite.getAsymetric()->getRawPublicKey());
    
    signatureData.push((byte)this->_cipherSuite.getAsymetric()->getRawPublicKey().size());
    signatureData.push(SECP251R1_CURVE, sizeof(word));
    signatureData.push((byte)NAMED_CURVE);
    signatureData.push(this->_serverRandom);
    signatureData.push(this->_clientRandom);

    this->_signature = this->_serverCertPrivateKey->createSignature(signatureData, _cipherSuite.getHash());
}

bool TLSServer::recvClientHello()
{
    bytes content;
    TLSRecord::recvPacket(_dstCom, content);
    size_t offset = 0;
    bytes dstServer;

    byte handshakeType = content[offset++];//handshake type
    offset += CONTENT_LENGTH_SIZE; // length
    word version = (word)bytesToInt(content, offset, offset + sizeof(word));//tls version
    offset += sizeof(word);
    this->_clientRandom.push(content.slice(offset, offset + RANDOM_STREAM_SIZE));//client random
    offset += RANDOM_STREAM_SIZE;

    
    byte sessionIdLength = content[offset++];//length of session id
    this->_clientSessionId.push(content.slice(offset, offset + sessionIdLength));//session id
    offset += sessionIdLength;
    word cipherSuitesLength = (word)bytesToInt(content, offset, offset + sizeof(word));//size of cipher suites
    offset += sizeof(word);
    bytes cipherSuites = content.slice(offset, offset + cipherSuitesLength);//cipher suites supported
    offset += cipherSuitesLength;
    word compressionTypeLength = content[offset++];//length of compression type
    bytes compressionType = content.slice(offset, offset + compressionTypeLength);//compression type
    offset += compressionTypeLength;
    const word extensionsLength = (word)bytesToInt(content, offset, offset + sizeof(word));//length of extensions
    offset += sizeof(word);
    size_t extensionBytesRead = 0;//bytes of extensions read, and list of the extensions

    std::vector<extension> extensions;//read all extensions
    while (extensionBytesRead < extensionsLength)
    {
        extension current;
        current.type = (word)bytesToInt(content, offset, offset + sizeof(word));//get the type
        offset += sizeof(word);
        extensionBytesRead += sizeof(word);
        
        current.extensionLength = (word)bytesToInt(content, offset, offset + sizeof(word));//get the length

        offset += sizeof(word);
        extensionBytesRead += sizeof(word);

        if (current.extensionLength > 0)//if length is greater than 0
        {
            current.data.push(content.slice(offset, offset + current.extensionLength));//get the data
            offset += current.extensionLength;
            extensionBytesRead += current.extensionLength;
            //extract the dstUrl if it is sni
            if (current.type == SERVER_NAME_INDEX_EXTENSION_TYPE && dstServer == "")
            {
                size_t sniOffset = 0;
                word sniLength = (word)bytesToInt(current.data, sniOffset, sniOffset + sizeof(word));
                sniOffset += sizeof(word);
                byte sniType = current.data[sniOffset++];
                word urlLength = (word)bytesToInt(current.data, sniOffset, sniOffset + sizeof(word));
                sniOffset += sizeof(word);

                dstServer.push(current.data.slice(sniOffset, sniOffset + urlLength));
                sniOffset += urlLength;

                _dst = dstServer;
            }
        }
        extensions.push_back(current);//push into list
    }

    _requests.push_back(new ClientHello(_clientRandom, _clientSessionId, dstServer, extensions, cipherSuites));
    return true;
}

bool TLSServer::sendServerHello()
{
    generateRandom(this->_serverRandom, RANDOM_STREAM_SIZE);
    generateRandom(this->_serverSessionId, SESSION_ID_SIZE);
    _cipherSuite.ComputeCipherSuite(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    
    std::vector<extension> extensions;

    extension renegotiationInfo;
    renegotiationInfo.type = RENEGOTIATION_INFO_EXTENSION_TYPE;
    renegotiationInfo.data.push(0x00);
    renegotiationInfo.extensionLength = (word)(renegotiationInfo.data.size());

    extension ecPointsFormat;
    ecPointsFormat.type = ELIPTIC_CURVE_POINT_FORMATS_EXTENSION_TYPE;
    bytes ecPointsFormatData({ 0x3, 0x0, 0x1, 0x2 });
    ecPointsFormat.data.push(ecPointsFormatData);
    ecPointsFormat.extensionLength = (word)(ecPointsFormat.data.size());

    extension sessionTicket;
    sessionTicket.type = SESSION_TICKET_EXTENSION_TYPE;
    sessionTicket.extensionLength = 0;

    extensions.push_back(renegotiationInfo);
    extensions.push_back(ecPointsFormat);
    //extensions.push_back(sessionTicket);

    ServerHello* serverHello = new ServerHello(_serverRandom, _serverSessionId, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, extensions);

    _requests.push_back(serverHello);

    return serverHello->send(_dstCom);
}

bool TLSServer::sendCertificates()
{
    std::vector<Certificate*> myCertificate;

    myCertificate.push_back(this->_serverCertificate);

    CertificateRequest* certificateRequest = new CertificateRequest(myCertificate);

    _requests.push_back(certificateRequest);

    return certificateRequest->send(_dstCom);
}

bool TLSServer::sendServerKeyExchange()
{
    generateSignature();
    ServerKeyExchange* serverKeyExchange = new ServerKeyExchange(this->_cipherSuite.getAsymetric()->getRawPublicKey(), this->_signature, RSA_PKCS1_SHA256_SIGNATURE_ALGORITHM, NAMED_CURVE, SECP251R1_CURVE);
    _requests.push_back(serverKeyExchange);

    return serverKeyExchange->send(_dstCom);;
}

bool TLSServer::sendServerHelloDone()
{
    ServerHelloDone* serverHelloDone = new ServerHelloDone();

    _requests.push_back(serverHelloDone);

    return serverHelloDone->send(_dstCom);
}

bool TLSServer::recvClientKeyExchange()
{
    bytes content;
    TLSRecord::recvPacket(_dstCom, content);
    size_t offset = 0;
    // only for ecdhe!
    byte handshakeType = content[offset++];
    offset += CONTENT_LENGTH_SIZE; // length

    byte pubKeyLen = content[offset++];
    _otherPublicKey.push(content.slice(offset, offset + pubKeyLen));
    offset += pubKeyLen;

    _requests.push_back(new ClientKeyExchange(_otherPublicKey));
    _masterSecret = _cipherSuite.KeyExchange(_otherPublicKey, _clientRandom, _serverRandom);

    return true;
}

bool TLSServer::recvClientEncryptedMessage()
{
    bytes content;
    TLSRecord::recvPacket(_dstCom, content);
    bytes allTraffic;
    bytes req;
    for (auto request : _requests)
    {
        req = request->toBytes();
        allTraffic.concat(req);
    }

    //change to update, but its singleton so we have problem
    bytes hashOfAllTraffic = _cipherSuite.getHash()->compute(allTraffic);
    bytes verifyData = prf_sha<CryptoPP::SHA256>(_masterSecret, "client finished", hashOfAllTraffic, VERIFY_DATA_LENGTH_AES_GCM_128);

    bytes header;
    header.push(0x0c);
    header.push(0, sizeof(word));
    header.push(0x14);

    verifyData.push(header);
    
    bytes text = _cipherSuite.getSymetric()->decrypt(content, TLS_HANDSHAKE);

    _requests.push_back(new EncryptedHandshakeMessage(verifyData));

    bool equal = text == verifyData;
    return equal;
}

bool TLSServer::sendServerEncryptedMessage()
{
    bytes allTraffic;
    bytes req;
    for (auto request : _requests)
    {
        req = request->toBytes();
        allTraffic.concat(req);
    }

    bytes hashOfAllTraffic = _cipherSuite.getHash()->compute(allTraffic);
    bytes verifyData = prf_sha<CryptoPP::SHA256>(_masterSecret, "server finished", hashOfAllTraffic, VERIFY_DATA_LENGTH_AES_GCM_128);

    bytes header;
    header.push(0x0C);
    header.push(0, sizeof(word));
    header.push(0x14);

    verifyData.push(header);

    bytes message = _cipherSuite.getSymetric()->encrypt(verifyData, TLS_HANDSHAKE);

    EncryptedHandshakeMessage* clientMessage = new EncryptedHandshakeMessage(message);

    _requests.push_back(clientMessage);

    return clientMessage->send(_dstCom);
}