#include "SessionHandlers.h"

std::unordered_set<std::string> HTTPSMITMProxy::whiteList = { "guthib.com" , "httpbin.org", "mmc.cyber.org.il" };
std::mutex HTTPSMITMProxy::whiteListLock;
unsigned long long ProxyHandler::_nextSessionId = 0;


ProxyHandler::ProxyHandler(SocketCommunicator* dstServerConnection, SocketCommunicator* clientConnection, bool ipv6) :
    _serverCon(dstServerConnection),
    _clientCon(clientConnection),
    _mySrcPort(dstServerConnection->getSrcPort()),
    _clientSrcPort(clientConnection->getDstPort()),
    _finished(false),
    _sessionId(ProxyHandler::generateUniqueId()),
    _ipv6(ipv6)
{

}

ProxyHandler::~ProxyHandler()
{
    if(this->_clientCon)
        this->_clientCon->closeSocket();
    if(this->_serverCon)
        this->_serverCon->closeSocket();

    delete this->_serverCon;
    delete this->_clientCon;
}

void ProxyHandler::closeSockets()
{
    this->_serverCon->closeSocket();
    this->_clientCon->closeSocket();
}

void ProxyHandler::proxy()
{
    auto clientFd = this->_clientCon->getFD();
    auto serverFd = this->_serverCon->getFD();
    fd_set read_fds;
    try
    {
        while (true)//purely tunneling, the data being transferred here is the tls session between chrome and the dst server
        {//we cant see it because we don't have the keys for this conversation
            FD_ZERO(&read_fds);
            FD_SET(clientFd, &read_fds);
            FD_SET(serverFd, &read_fds);

            int max_fd = (int)(max(clientFd, serverFd) + 1);

            if (select(max_fd, &read_fds, NULL, NULL, NULL) == SOCKET_ERROR)
                throw std::exception("Select Error");

            if (FD_ISSET(clientFd, &read_fds)) {
                bytes request;
                this->_clientCon->recvBuff(request);
                if (request.empty())
                    continue;
                this->_serverCon->send(request, request.size());
            }

            if (FD_ISSET(serverFd, &read_fds)) {
                bytes response;
                this->_serverCon->recvBuff(response);
                if (response.empty())
                    continue;
                this->_clientCon->send(response, response.size());
            }


        }
    }
    catch (const std::exception& e)
    {
        std::cout << e.what() << std::endl;
        this->_finished = true;
    }
}

void ProxyHandler::sendClient(const bytes& response)
{
    this->_clientCon->send(response, response.size());
}

void ProxyHandler::sendServer(const bytes& request)
{
    this->_serverCon->send(request, request.size());
}

const unsigned long long ProxyHandler::getSessionId() const
{
    return this->_sessionId;
}

bool ProxyHandler::finished()
{
    return this->_finished;
}

unsigned short ProxyHandler::getMySrcPort()
{
    return this->_mySrcPort;
}

unsigned short ProxyHandler::getClientSrcPort()
{
    return this->_clientSrcPort;
}




HTTPSMITMProxy::HTTPSMITMProxy(SocketCommunicator* dstServerConnection, SocketCommunicator* clientConnection, const std::string& dstHost, bool ipv6) : ProxyHandler(dstServerConnection, clientConnection, ipv6)
{
    this->_tlsClient = nullptr;
    this->_tlsServer = nullptr;
    this->_dstHostname = dstHost;
    std::cout << "Connected to " << this->_dstHostname << std::endl;
    static const CertDataPaths caCertPaths{ "ca_cert.pem", "ca_key.pem"};
    try
    {
        CertDataPaths signedCertPaths = Certificate::generateSignedCertificate(caCertPaths, dstHost);
        if (signedCertPaths.certPath == "" || signedCertPaths.keyPath == "")
            throw std::exception("Failed to generate certificate!");
        this->_tlsServer = new TLSServer(signedCertPaths.certPath, signedCertPaths.keyPath, this->_clientCon);
        this->_tlsServer->listen();

        this->_tlsClient = new TLS(this->_dstHostname, this->_serverCon);
        this->_tlsClient->do_handshake();
        this->_setupSuccessful = true;
    }
    catch (const std::exception& e)
    {
        if (this->_tlsServer && this->_tlsServer->Connected() && this->_tlsClient && !(this->_tlsClient->Connected()))
        {
            this->_tlsServer->recv();
            this->_tlsServer->send(HawkErrorPage);
        }
        std::cout << e.what() << " " << dstHost << std::endl;
        this->_setupSuccessful = false;
    }
}

HTTPSMITMProxy::~HTTPSMITMProxy()
{
    delete this->_tlsClient;
    delete this->_tlsServer;
}

bool HTTPSMITMProxy::addHost(const std::string& host)
{
    std::lock_guard<std::mutex> lock(HTTPSMITMProxy::whiteListLock);
    HTTPSMITMProxy::whiteList.insert(host);
    return true;
}

void HTTPSMITMProxy::removeHost(const std::string& host)
{
    std::lock_guard<std::mutex> lock(HTTPSMITMProxy::whiteListLock);
    if(HTTPSMITMProxy::whiteList.count(host) > 0)
        HTTPSMITMProxy::whiteList.erase(host);
}

std::vector<std::string> HTTPSMITMProxy::getAcceptedHosts()
{
    std::lock_guard<std::mutex> lock(HTTPSMITMProxy::whiteListLock);
    std::vector<std::string> hosts;
    for (const auto& host : HTTPSMITMProxy::whiteList)
        hosts.push_back(host);

    return hosts;
}

//not calling the sockets directly, we need to call the tls client/server
void HTTPSMITMProxy::sendClient(const bytes& response)
{
    this->_tlsServer->send(response);
}

void HTTPSMITMProxy::sendServer(const bytes& request)
{
    this->_tlsClient->send(request);
}

bool HTTPSMITMProxy::acceptedHost(const std::string& host)
{
    std::lock_guard<std::mutex> lock(HTTPSMITMProxy::whiteListLock);
    return (HTTPSMITMProxy::whiteList.count(host) > 0);
}

//does it work????
void HTTPSMITMProxy::proxy()
{
    auto clientFd = this->_clientCon->getFD();
    fd_set read_fds;
    auto serverFd = this->_serverCon->getFD();
    try
    {
        while (true)
        {
            FD_ZERO(&read_fds);
            FD_SET(clientFd, &read_fds);
            FD_SET(serverFd, &read_fds);
            int max_fd = (int)(max(clientFd, serverFd) + 1);
            if (select(max_fd, &read_fds, NULL, NULL, NULL) == SOCKET_ERROR)
                throw std::exception("Select Error");

            if (FD_ISSET(clientFd, &read_fds)) {
                HTTPRequest request = HTTPSMITMCon::recvHttps(*(this->_tlsServer));
                if (request.getRaw().empty())
                    continue;
                if (ProxyServer::intercept())
                {
                    auto* data = new HTTPApplicationData(this, true, TO_SERVER, request, this->getSessionId());
                    ProxyServer::pushAppData(data);
                }
                else
                {
                    auto* data = new HTTPApplicationData(this, false, TO_SERVER, request, this->getSessionId());
                    ProxyServer::pushAppData(data);
                    this->_tlsClient->send(request.getRaw());
                }
            }
            if (FD_ISSET(serverFd, &read_fds)) {
                HTTPRequest response = HTTPSMITMCon::recvHttps(*(this->_tlsClient));
                if (response.getRaw().empty())
                    continue;
                if (ProxyServer::intercept())
                {
                    auto* data = new HTTPApplicationData(this, true, TO_CLIENT, response, this->getSessionId());
                    ProxyServer::pushAppData(data);
                }
                else
                {
                    auto* data = new HTTPApplicationData(this, false, TO_CLIENT, response, this->getSessionId());
                    ProxyServer::pushAppData(data);
                    this->_tlsServer->send(response.getRaw());
                }
            }
        }
    }
    catch (const std::exception& e)
    {
        std::cout << e.what() << std::endl;
        _finished = true;
    }
}


HTTPSTunnelProxy::HTTPSTunnelProxy(SocketCommunicator* serverCon, SocketCommunicator* clientCon, bool ipv6) : ProxyHandler(serverCon, clientCon, ipv6)
{
   
}


HTTPMITMProxy::HTTPMITMProxy(SocketCommunicator* dstServerConnection, SocketCommunicator* clientConnection, bool ipv6) : ProxyHandler(dstServerConnection, clientConnection, ipv6)
{
}


void HTTPMITMProxy::proxy()
{
    auto clientFd = this->_clientCon->getFD();
    auto serverFd = this->_serverCon->getFD();
    fd_set read_fds;
    try
    {
        while (true)
        {
            FD_ZERO(&read_fds);
            FD_SET(clientFd, &read_fds);
            FD_SET(serverFd, &read_fds);
            int max_fd = (int)(max(clientFd, serverFd) + 1);
            if (select(max_fd, &read_fds, NULL, NULL, NULL) == SOCKET_ERROR)
                throw std::exception("Select Error");

            if (FD_ISSET(clientFd, &read_fds)) {
                HTTPRequest request = Connection::recvHttp(*(this->_clientCon));
                if (request.getRaw().empty())
                    continue;
                if (ProxyServer::intercept())
                {
                    auto* data = new HTTPApplicationData(this, true, TO_SERVER, request, this->getSessionId());
                    ProxyServer::pushAppData(data);
                }
                else
                {
                    //was not intercepted!                     false
                    auto* data = new HTTPApplicationData(this, false, TO_SERVER, request, this->getSessionId());
                    ProxyServer::pushAppData(data);
                    this->_serverCon->send(request.getRaw(), request.getRaw().size());
                }
            }
            if (FD_ISSET(serverFd, &read_fds)) {
                HTTPRequest response = Connection::recvHttp(*(this->_serverCon));
                if (response.getRaw().empty())
                    continue;
                if (ProxyServer::intercept())
                {
                    auto* data = new HTTPApplicationData(this, true, TO_CLIENT, response, this->getSessionId());
                    ProxyServer::pushAppData(data);
                }
                else
                {
                    //was not intercepted!                     false
                    auto* data = new HTTPApplicationData(this, false, TO_CLIENT, response, this->getSessionId());
                    ProxyServer::pushAppData(data);
                    this->_clientCon->send(response.getRaw(), response.getRaw().size());
                }
            }
        }
    }
    catch (const std::exception& e)
    {
        std::cout << e.what() << std::endl;
        _finished = true;
    }
}


GeneralMITMProxy::GeneralMITMProxy(SocketCommunicator* dstServerConnection, SocketCommunicator* clientConnection, bool ipv6) : ProxyHandler(dstServerConnection, clientConnection, ipv6)
{
}

void GeneralMITMProxy::proxy()
{
    auto clientFd = this->_clientCon->getFD();
    auto serverFd = this->_serverCon->getFD();
    fd_set read_fds;
    try
    {
        while (true)//purely tunneling, the data being transferred here is the tls session between chrome and the dst server
        {//we cant see it because we don't have the keys for this conversation
            FD_ZERO(&read_fds);
            FD_SET(clientFd, &read_fds);
            FD_SET(serverFd, &read_fds);

            int max_fd = (int)(max(clientFd, serverFd) + 1);

            if (select(max_fd, &read_fds, NULL, NULL, NULL) == SOCKET_ERROR)
                throw std::exception("Select Error");

            if (FD_ISSET(clientFd, &read_fds)) {
                bytes request;
                this->_clientCon->recvBuff(request);
                if (request.empty())
                    continue;
                if (ProxyServer::intercept())
                {
                    auto* data = new GeneralData(this, true, TO_SERVER, request, this->getSessionId());
                    ProxyServer::pushAppData(data);
                }
                else
                {
                    auto* data = new GeneralData(this, false, TO_SERVER, request, this->getSessionId());
                    ProxyServer::pushAppData(data);
                    this->_serverCon->send(request, request.size());
                }
            }
            if (FD_ISSET(serverFd, &read_fds)) {
                bytes response;
                this->_serverCon->recvBuff(response);
                if (response.empty())
                    continue;
                if (ProxyServer::intercept())
                {
                    auto* data = new GeneralData(this, true, TO_CLIENT, response, this->getSessionId());
                    ProxyServer::pushAppData(data);
                }
                else
                {
                    auto* data = new GeneralData(this, false, TO_CLIENT, response, this->getSessionId());
                    ProxyServer::pushAppData(data);
                    this->_clientCon->send(response, response.size());
                }
            }
        }
    }
    catch (const std::exception& e)
    {
        std::cout << e.what() << std::endl;
        this->_finished = true;
    }
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








SessionHandler::SessionHandler(const PacketStack& ps) : _ps(ps), _closeSession(false)
{
    ;
}
SessionHandler::SessionHandler() : _ps(), _closeSession(false)
{
    ;
}
SessionHandler::~SessionHandler()
{
    for (auto& c : this->_ps)
    {
        delete c;
        c = nullptr;
    }
    for (auto& c : this->_psPending)
    {
        delete c;
        c = nullptr;
    }
}


PacketStack& SessionHandler::getPackets()
{
    return this->_ps;
}
PacketStack& SessionHandler::getPending()
{
    return this->_psPending;
}
void SessionHandler::clearPending()
{
    for (auto& p : this->_psPending)
    {
        delete p;
        p = nullptr;
    }

    this->_psPending.clear();
}
void SessionHandler::push_back(WinDivertPacket* p)
{
    this->_ps.push_back(p);
}

bool SessionHandler::closeSession()
{
    return this->_closeSession;
}






MitmHandler::MitmHandler() : _clientCom(new StreamCommunicator), _serverCom(new StreamCommunicator)
{
    this->_clientSeqDelta = 0;
    this->_clientAckDelta = 0;

    this->_serverSeqDelta = 0;
    this->_serverAckDelta = 0;

    this->_tcp = true;
    this->_tcpHandshakeDone = false;

    this->_beginHandshake = 0;
    this->_finishHandshake = 0;
    this->_finishHandshakeOther = 0;
}

MitmHandler::~MitmHandler()
{
    delete this->_clientCom;
    delete this->_serverCom;
}

void MitmHandler::push_back(WinDivertPacket* p)
{
    //first packet
    TCP_FLAGS flags = p->getTcpFlags();
    if (this->_ps.empty() && !flags.syn)
    {
        this->_closeSession = true;//only want to mitm new sessions, that start with syn flag
    }

    trackFinFlags(flags);

    accountForDelta(p);

    if (p->getPayloadSize() == 0)
    {
        this->_ps.push_back(p);
        WinDivertPacket* newPacket = new WinDivertPacket(*p);
        this->_psPending.push_back(newPacket);
        return;
    }

    if (isPacketRetransmission(p))
    {
        std::cout << "    Dropped Retransmission!" << std::endl;
        return;
    }


    this->_ps.push_back(p);

    this->handle(p);


}

void MitmHandler::handle(WinDivertPacket* p)
{
    WinDivertPacket* newPacket = new WinDivertPacket(*p);
    if (p->getOutbound())
    {
        //could set payload here

        this->_clientSeqDelta += newPacket->getPayloadSize() - p->getPayloadSize();
        this->_serverAckDelta += this->_clientSeqDelta;
    }
    else
    {
        newPacket->setPayload(bytes("Hello"));
        this->_serverSeqDelta += newPacket->getPayloadSize() - p->getPayloadSize();
        this->_clientAckDelta += this->_serverSeqDelta;
    }

    this->_psPending.push_back(newPacket);
}

void MitmHandler::trackFinFlags(TCP_FLAGS flags)
{
    switch (this->_finishHandshake)
    {
    case 0:
        if (flags.fin && flags.ack)
        {
            this->_finishHandshake++;
            this->_finishHandshakeOther++;
        }
        break;
    case 1:
        if (flags.ack)
            this->_finishHandshake++;
        else if (flags.ack && flags.fin)
            this->_finishHandshakeOther++;
        else
        {
            this->_finishHandshake = 0;
            this->_finishHandshakeOther = 0;
        }
        break;
    case 2:
        if (flags.ack && flags.fin)
            this->_finishHandshake++;
        else if (flags.ack)
            this->_finishHandshakeOther++;
        else
        {
            this->_finishHandshake = 0;
            this->_finishHandshakeOther = 0;
        }
        break;
    case 3:
        if (flags.ack)
        {
            this->_finishHandshake++;
            this->_finishHandshakeOther++;
        }
        else
        {
            this->_finishHandshake = 0;
            this->_finishHandshakeOther = 0;
        }
        break;
    }
    if (this->_finishHandshake == FINISHED_LAST_HANDSHAKE || this->_finishHandshakeOther == FINISHED_LAST_HANDSHAKE)
        this->_closeSession = true;
}

void MitmHandler::accountForDelta(WinDivertPacket* p)
{
    size_t oldSeq = ntohl(p->getTcpLayer()->SeqNum);
    size_t oldAck = ntohl(p->getTcpLayer()->Ack);

    if (p->getOutbound())
        p->setPacketSeqAck(oldSeq + this->_clientSeqDelta, oldAck + this->_clientAckDelta);
    else
        p->setPacketSeqAck(oldSeq + this->_serverSeqDelta, oldAck + this->_serverAckDelta);

}

bool MitmHandler::isPacketRetransmission(WinDivertPacket* p)
{
    bool packetDirection = p->getOutbound();
    if (p->isTCP() && this->_ps.size() > 0)
    {
        Packet* lastTcp = nullptr;
        size_t i = 0;
        for (i = this->_ps.size() - 1; i > 0; i--)
        {
            if ((this->_ps[i])->isTCP() && (this->_ps[i])->getOutbound() == packetDirection && this->_ps[i]->getPayloadSize() > 0)
            {
                lastTcp = this->_ps[i];
                break;
            }
        }
        if (lastTcp)
        {
            bool isRetransmission = true;//retransmission has same ack and seq
            isRetransmission = isRetransmission && p->getTcpLayer()->SeqNum == lastTcp->getTcpLayer()->SeqNum;
            isRetransmission = isRetransmission && p->getTcpLayer()->Ack == lastTcp->getTcpLayer()->Ack;
            return isRetransmission;
        }
    }
    return false;
}

