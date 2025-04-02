#include "TlsRecords.h"

bool TLSRecord::send(Communicator& com, byte type)
{
    bytes headers;
    bytes request = toBytes();

    headers.push(request.size(), sizeof(word));
    headers.push(TLS_VERSION, sizeof(word));
    headers.push(type);

    headers += request;

    //return com.send(headers, headers.size()) && com.send(request, request.size());
    return com.send(headers, headers.size());
    //meed to check, makes a few problems
}

bool TLSRecord::send(Communicator& com, const bytes& data, byte type)
{
    bytes headers;

    headers.push(data.size(), sizeof(word));
    headers.push(TLS_VERSION, sizeof(word));
    headers.push(type);

    //again, this fixes some problem that happends sometimes
    headers += data;

    return com.send(headers, headers.size());
    //return com.send(headers, headers.size()) && com.send(data, data.size());
}

void TLSRecord::recvPacket(Communicator& com, bytes& buffer)
{
    bytes headers(TLS_HEADER_SIZE);

    com.recv(headers, TLS_HEADER_SIZE);

    byte contentType = (byte)headers[0];
    word tlsVersion = (word)bytesToInt(headers, sizeof(byte), sizeof(byte) + sizeof(word));
    word requestLength = (word)bytesToInt(headers, 3, 3 + sizeof(word));

    //buffer.clear();
    //buffer.resize(requestLength);
    //communicator takes care of resizing the buffer

    com.recv(buffer, requestLength);
}


void TLSRecord::peekPacket(SocketCommunicator& com, bytes& buffer)
{
    bytes headers(TLS_HEADER_SIZE);

    com.peek(headers, TLS_HEADER_SIZE);

    byte contentType = (byte)headers[0];
    word tlsVersion = (word)bytesToInt(headers, sizeof(byte), sizeof(byte) + sizeof(word));
    word requestLength = (word)bytesToInt(headers, 3, 3 + sizeof(word));

    //buffer.clear();
    //buffer.resize(requestLength);
    //communicator takes care of resizing the buffer

    com.peek(buffer, requestLength + TLS_HEADER_SIZE);


    //remove the headers, because peek doesn't remove it from stream
    buffer = buffer.substr(TLS_HEADER_SIZE, buffer.size() - TLS_HEADER_SIZE);
}




const bytes ClientHello::toBytes()
{
    bytes request;
    const int sizeofSessionId = SESSION_ID_SIZE;
    const int sizeofRandom = RANDOM_STREAM_SIZE;

    //if no extensions given, use default extensions
    if (this->_extensions.size() == 0)
    {
        //extensions
        byte rawExtensions[] = {
            // Extension: EC Point Formats
            0x00, 0x0b,  // Extension type(EC Point Formats)
            0x00, 0x02,  // Length
            0x01,  // EC Point Formats length
            0x00,  // uncompressed

            // Extension: supported groups
            0x00, 0x0a,
            0x00, 0x06,
            0x00, 0x04,
            0x00, 0x17,
            0x00, 0x18,

            // Extension: renegotiation_info
            0xff, 0x01,
            0x00, 0x01,
            0x00,

            // Extension : supported versions
            0x00, 0x2b,  // Extension type
            0x00, 0x03,  // Length
            0x02,  // Supported version length
            0x03, 0x03,  // TLS 1.2

            // Extension: signature algorithm
            0x00, 0x0d,  // Extension type
            0x00, 0x12,  // Length
            0x00, 0x10,  // Algorithms length
            0x06, 0x01,
            0x06, 0x03,
            0x05, 0x01,
            0x05, 0x03,
            0x04, 0x01,
            0x04, 0x03,
            0x02, 0x01,
            0x02, 0x03
        };
        bytes extensions(rawExtensions, sizeof(rawExtensions));

        //insert the extensions
        request.push(extensions);

        //insert the url
        request.push(_dst);  //copy url
        word urlLen = (word)_dst.length();  //get its length

        request.push(urlLen, sizeof(word));
        request.push(0x0);
        request.push(urlLen + 3, sizeof(word));
        request.push(urlLen + 5, sizeof(word));

        request.push(0x0000, sizeof(word));
    }
    else//if we got extensions
    {
        bytes extensions;
        bytes extension;
        for (const auto& ext : _extensions)
        {
            extension.clear();
            extension.push(ext.data);
            extension.push(ext.extensionLength, sizeof(word));
            extension.push(ext.type, sizeof(word));

            extensions.concat(extension);
        }
        request.push(extensions);
    }

    const word extensionsLength = (const word)request.size();
    request.push(extensionsLength, sizeof(word));

    request.push(0x0100, sizeof(word));

    request.push(_cipherSuites);
    request.push(_cipherSuites.size(), sizeof(word));

    request.push(_sessionId);
    request.push((byte)(_sessionId.size()));  //size of session id

    request.push(_random);

    request.push(TLS_VERSION, sizeof(word));  // tls v1.2
    request.push(request.size(), CONTENT_LENGTH_SIZE);  // content size

    request.push(CLIENT_HELLO_HANDSHAKE_TYPE);  //handshake type, client hello

    return request;
}

const bytes ServerHello::toBytes()
{
    bytes request;

    bytes extensions;
    bytes extension;

    for (auto& ext : _extensions)
    {
        extension = bytes();

        extension.push(ext.data);
        extension.push(ext.extensionLength, sizeof(word));
        extension.push(ext.type, sizeof(word));

        extensions.concat(extension);
    }

    request.push(extensions);
    request.push(extensions.size(), sizeof(word));

    request.push(NULL); // compression methods

    // find overlapping cipher suites between server and client
    // for now just return TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

    request.push(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, sizeof(word));
    request.push(_sessionId);
    request.push((byte)_sessionId.size());

    request.push(_random);

    request.push(TLS_VERSION, sizeof(word));
    request.push(request.size(), CONTENT_LENGTH_SIZE);
    request.push(SERVER_HELLO_HANDSHAKE_TYPE);

    return request;
}

const bytes CertificateRequest::toBytes()
{
    bytes request;
    bytes certRaw;
    size_t totalSize = 0;

    for (auto& cert : _certs)
    {
        certRaw = cert->getRaw();
        certRaw.push(certRaw.size(), CONTENT_LENGTH_SIZE);

        request.concat(certRaw);

        totalSize += certRaw.size();
    }

    request.push(totalSize, CONTENT_LENGTH_SIZE);
    request.push(totalSize + CONTENT_LENGTH_SIZE, CONTENT_LENGTH_SIZE);
    request.push(CERTIFICATE_HANDSHAKE_TYPE);

    return request;
}

const bytes ServerKeyExchange::toBytes()
{
    bytes request;

    request.push(_signature);
    request.push(_signature.size(), sizeof(word));
    request.push(_signatureAlgo, sizeof(word));

    request.push(_pubKey);
    request.push((byte)_pubKey.size());

    request.push(_namedCurve, sizeof(word));
    request.push(_curveType);

    request.push(request.size(), CONTENT_LENGTH_SIZE);
    request.push(SERVER_KEY_EXCHANGE_HANDSHAKE_TYPE);

    return request;
}

const bytes ClientKeyExchange::toBytes()
{
    bytes request;

    request.push(_pubKey); // public key

    request.push((byte)_pubKey.size()); // size of public key

    request.push(sizeof(byte) + _pubKey.size(), CONTENT_LENGTH_SIZE); // content length

    request.push(CLIENT_KEY_EXCHANGE_HANDSHAKE_TYPE);

    return request;
}

const bytes ServerHelloDone::toBytes()
{
    bytes content;

    content.push(NULL, CONTENT_LENGTH_SIZE);
    content.push(SERVER_HELLO_DONE_HANDSHAKE_TYPE);


    return content;
}

const bytes EncryptedHandshakeMessage::toBytes()
{
    return this->_message;
}
