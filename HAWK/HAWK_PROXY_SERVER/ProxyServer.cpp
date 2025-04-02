#include "ProxyServer.hpp"

//simple windivert proxy server
unsigned short ProxyServer::_listeningPort = 0;
std::string ProxyServer::_myIp = getLocalIPAddress();
std::string ProxyServer::_myIpv6 = getLocalIPV6Address();
const bool ProxyServer::ipv6Available = !(ProxyServer::_myIpv6.empty());
const bool ProxyServer::ipv4Available = !(ProxyServer::_myIp.empty());

LockFreeQueue<ApplicationData> ProxyServer::_pendingData;

std::mutex ProxyServer::_proxySessionsLock;
std::unordered_set<ProxyHandler*> ProxyServer::_proxySessions;
std::mutex ProxyServer::_proxyThreadsLock;
std::unordered_map<ProxyHandler*, std::thread> ProxyServer::_proxyThreads;

size_t ProxyServer::packetsTransfered = 0;
double ProxyServer::mbTransfered = 0;

bool ProxyServer::_intercept = false;

// *** proxy ***
ProxyServer::ProxyServer(unsigned short port) :_divertedPort(port), 
_wd(port),  //init windivert
_runProxy(true) //for gui, this should probably be turned off at instatination
{//init the listening socket, packets would get redirected there

    //calculate our listening port
    this->_listeningPort = ((PROXY_SERVER_PORT == port) ? ALTERNATE_PROXY_SERVER_PORT : PROXY_SERVER_PORT);//listening port should be the same for both ipv6 and ipv6 listening sockets

    if(ProxyServer::ipv6Available)
        _ipv6ListeningSocket = new SocketCommunicator(std::to_string(this->_listeningPort), true, true); //init ipv6 listening socket
    if(ProxyServer::ipv4Available)
        _listeningSocket = new SocketCommunicator(std::to_string(this->_listeningPort), true); //init listening socket


    //start listening thread
    //this thread will listen for new socket connections, and handle them
    this->_listeningThread = new std::thread(&ProxyServer::acceptNewClients, this);
    this->_listeningThread->detach();

    this->_ipv6ListeningThread = new std::thread(&ProxyServer::acceptNewIpv6Clients, this);
    this->_ipv6ListeningThread->detach();



    
}
ProxyServer::~ProxyServer()
{
    this->_listening = false;
    this->_pendingData.close();
    {
        std::lock_guard<std::mutex> lock(this->_proxyThreadsLock);

        std::lock_guard<std::mutex> lock1(this->_proxySessionsLock);

        //iterate them all
        for (auto it = this->_proxySessions.begin(); it != this->_proxySessions.end(); it++)
        {
            ProxyHandler* session = *it;
            if (!session)
                continue;
            
            session->closeSockets();

            if (this->_proxyThreads.count(session) > 0)
            {
                if (this->_proxyThreads[session].joinable())
                    this->_proxyThreads[session].join();
                this->_proxyThreads.erase(session);//remove the session
            }

            delete session;
        }


        
        this->_proxySessions.clear();//after we deleted all the pointers, we can clear the set

        std::lock_guard<std::mutex> lock2(this->_srcPortToIpLock);
        this->_srcPortToIp.clear();
        std::lock_guard<std::mutex> lock3(this->_portSetLock);
        this->_ourSrcPorts.clear();

    }

    if(_listeningSocket)
        _listeningSocket->closeSocket();
    if(_ipv6ListeningSocket)
        _ipv6ListeningSocket->closeSocket();

    if (_listeningThread->joinable())
        _listeningThread->join();
    if (_ipv6ListeningThread->joinable())
        _ipv6ListeningThread->join();

    delete _listeningThread;
    delete _ipv6ListeningThread;

    delete _listeningSocket;
    delete _ipv6ListeningSocket;
}



/*
  _____ __  __ _____   ____  _____ _______       _   _ _______
 |_   _|  \/  |  __ \ / __ \|  __ \__   __|/\   | \ | |__   __|
   | | | \  / | |__) | |  | | |__) | | |  /  \  |  \| |  | |
   | | | |\/| |  ___/| |  | |  _  /  | | / /\ \ | . ` |  | |
  _| |_| |  | | |    | |__| | | \ \  | |/ ____ \| |\  |  | |
 |_____|_|  |_|_|     \____/|_|  \_\ |_/_/    \_\_| \_|  |_|
*/

//all the windivert component does is redirect outbound packets to our own server
void ProxyServer::startProxy()
{
    this->_pendingData.reopen();
    startCleanupThread();//start the cleanup thread
    _wd.setWinDivert();
    _runProxy = true;
    WinDivertPacket* p = nullptr;
    const size_t IPV6_ADDR_SIZE = 16;
    //std::unique_lock<std::mutex> outerLock(this->_wdLock, std::defer_lock);
    std::string dstIp = "";
    std::string originalIp = "";
    while (_runProxy)
    {
        p = _wd.recv();
        if (!p)
            continue;

        ProxyServer::packetsTransfered++;
        ProxyServer::mbTransfered += p->getPacketSize() * 0.000001;
        
        try
        {
            if (this->isOurPacket(p))//if the request is ours (src port is in ourSrcPorts set)
            {
                _wd.sendPacket(p);
                delete p;
                continue;
            }
            updateIpLUT(p);//update src port to original dst ip LUT (Look Up Table)
            //check if packet is one from our own clients (we don't want to divert those)
            if (p->getIpLayer() && p->getIpLayer()->DstAddr == p->getIpLayer()->SrcAddr)//the test is whether the src ip is equal to the dst ip
            {
                std::lock_guard<std::mutex> lock(this->_srcPortToIpLock);
                p->setPacketSrcIpPort(this->_srcPortToIp[p->getDstPort()], this->_divertedPort);
            }
            else if (p->getIpv6Layer() && memcmp(p->getIpv6Layer()->DstAddr, p->getIpv6Layer()->SrcAddr, IPV6_ADDR_SIZE) == 0)
            {
                std::lock_guard<std::mutex> lock(this->_srcPortToIpv6Lock);
                p->setPacketSrcIpPort(this->_srcPortToIpv6[p->getDstPort()], this->_divertedPort);
            }
            else
            {
                if (p->getIpLayer())
                    p->setPacketDstIpPort(this->_myIp, this->_listeningPort);//divert back to us
                else if (p->getIpv6Layer())
                    p->setPacketDstIpPort(this->_myIpv6, this->_listeningPort);//divert back to us
            }
            _wd.sendPacket(p);//FUcking Gneius
            delete p;
        }
        catch (...){}


    }
}


void ProxyServer::acceptNewClients() const
{
    if (!(ProxyServer::ipv4Available))
        return;
    SocketCommunicator* clientConnection = nullptr, * dstServerConnection = nullptr;
    ProxyHandler* proxyHandler = nullptr;
    SOCKET clientSock = INVALID_SOCKET;
    std::string dstIp = "";
    unsigned short addedPort = 0, clientPort = 0;
    while (this->_listening)
    {
        clientConnection = nullptr, dstServerConnection = nullptr, proxyHandler = nullptr;
        clientSock = INVALID_SOCKET;
        addedPort = 0, clientPort = 0;
        dstIp.clear();
        try
        {
            if(this->_listeningSocket)
                clientSock = this->_listeningSocket->accept();
            if (clientSock == INVALID_SOCKET)
                continue;

            clientConnection = new SocketCommunicator(clientSock);
            dstServerConnection = new SocketCommunicator();
            clientPort = clientConnection->getDstPort();
            dstIp = srcPortToIp(clientPort);

            dstServerConnection->bind();//bind to already assign the src port
            addedPort = dstServerConnection->getSrcPort();
            addPortToSet(addedPort);

            dstServerConnection->connect(dstIp, std::to_string(this->_divertedPort));//won't be diverted because we added it to list of ports

            proxyHandler = createNewSession(dstServerConnection, clientConnection);
            if (proxyHandler && proxyHandler->setupSuccess())
            {
                addProxySession(proxyHandler);
                std::lock_guard<std::mutex> lock(ProxyServer::_proxyThreadsLock);
                ProxyServer::_proxyThreads[proxyHandler] = std::thread(& ProxyHandler::proxy, proxyHandler);
            }
        }
        catch (const std::exception& e)
        {
            if (!proxyHandler)
            {
                std::lock_guard<std::mutex> lock1(this->_srcPortToIpLock);
                this->_srcPortToIp.erase(clientPort);
                std::lock_guard<std::mutex> lock2(this->_portSetLock);
                this->_ourSrcPorts.erase(addedPort);
            }
            try
            {
                if (clientConnection && !proxyHandler)
                    delete clientConnection;
                if (dstServerConnection && !proxyHandler)
                    delete dstServerConnection;
            }
            catch (...){}
            std::cout << e.what() << std::endl;
        }
    }
}

void ProxyServer::acceptNewIpv6Clients() const
{
    if (!(ProxyServer::ipv6Available))
        return;
    SocketCommunicator* clientConnection = nullptr, *dstServerConnection = nullptr;
    ProxyHandler* proxyHandler = nullptr;
    SOCKET clientSock = INVALID_SOCKET;
    std::string dstIp = "";
    unsigned short addedPort = 0, clientPort = 0;
    while (this->_listening)
    {
        clientConnection = nullptr, dstServerConnection = nullptr, proxyHandler = nullptr;
        clientSock = INVALID_SOCKET;
        addedPort = 0, clientPort = 0;
        dstIp.clear();
        try
        {
            if(this->_ipv6ListeningSocket)
                clientSock = this->_ipv6ListeningSocket->accept();
            if (clientSock == INVALID_SOCKET)
                continue;
            //turn to socket communicator
            clientConnection = new SocketCommunicator(clientSock, true);
            dstServerConnection = new SocketCommunicator(true);

            clientPort = clientConnection->getDstPort();
            dstIp = this->srcPortToIpv6(clientPort);

            dstServerConnection->bind();//dumbest fucking shit ever
            addedPort = dstServerConnection->getSrcPort();
            addPortToSetIpv6(addedPort);

            dstServerConnection->connect(dstIp, std::to_string(this->_divertedPort));

            proxyHandler = createNewSession(dstServerConnection, clientConnection, true);
            if (proxyHandler && proxyHandler->setupSuccess())
            {
                addProxySession(proxyHandler);
                std::lock_guard<std::mutex> lock(ProxyServer::_proxyThreadsLock);
                ProxyServer::_proxyThreads[proxyHandler] = std::thread(&ProxyHandler::proxy, proxyHandler);
            }
        }
        catch (const std::exception& e)
        {
            if (!proxyHandler)
            {
                std::lock_guard<std::mutex> lock1(this->_srcPortToIpv6Lock);
                this->_srcPortToIpv6.erase(clientPort);
                std::lock_guard<std::mutex> lock2(this->_ipv6PortSetLock);
                this->_ourIpv6SrcPorts.erase(addedPort);
            }
            try
            {
                if (clientConnection && !proxyHandler)
                    delete clientConnection;
                if (dstServerConnection && !proxyHandler)
                    delete dstServerConnection;
            }
            catch (...){;}
            std::cout << e.what() << std::endl;
        }
    }
}

/*
  _____ __  __ _____   ____  _____ _______       _   _ _______
 |_   _|  \/  |  __ \ / __ \|  __ \__   __|/\   | \ | |__   __|
   | | | \  / | |__) | |  | | |__) | | |  /  \  |  \| |  | |
   | | | |\/| |  ___/| |  | |  _  /  | | / /\ \ | . ` |  | |
  _| |_| |  | | |    | |__| | | \ \  | |/ ____ \| |\  |  | |
 |_____|_|  |_|_|     \____/|_|  \_\ |_/_/    \_\_| \_|  |_|
*/

void ProxyServer::stopProxy()
{
    this->_wd.unsetWindivert();//unset the windivert
    _runProxy = false;
}
void ProxyServer::toggleIntercept()
{
    _intercept = !_intercept;
}

void ProxyServer::closeIntercept()
{
    _intercept = false;
}

bool ProxyServer::intercept()
{
    return ProxyServer::_intercept;
}

unsigned short ProxyServer::getListeningPort()
{
    return ProxyServer::_listeningPort;
}

ApplicationData* ProxyServer::pullAppData()
{
    ApplicationData* appData = ProxyServer::_pendingData.pop();
    return appData;
}

void ProxyServer::pushAppData(ApplicationData* appData)
{
    ProxyServer::_pendingData.push(appData);
}

void ProxyServer::halt()
{
    ProxyServer::_pendingData.close();
}

void ProxyServer::forwardAppData(ApplicationData* appData)
{
    std::lock_guard<std::mutex> lock(ProxyServer::_proxySessionsLock);
    ProxyHandler* parent = (ProxyHandler*)(appData->getParent());
    //if we need to forward data (meaning, we intercepted it and need to forward it OR we intercepted it and blocked it), and session exists
    if (appData->forwardData() && ProxyServer::_proxySessions.count((ProxyHandler*)parent) != 0)
    {
        //make sure its not just randomly the same pointer
        if (parent->getSessionId() == appData->getSessionId() && !(parent->finished()))
        {
            const bytes& rawData = appData->getRawData();
            auto direction = appData->getDirection();
            if (direction == TO_SERVER)
                parent->sendServer(rawData);
            else if (direction == TO_CLIENT)
                parent->sendClient(rawData);

            appData->block();//already sent, no need to forward again
        }
    }
}



void ProxyServer::startCleanupThread()
{
    std::thread([this]() {
        while (_runProxy)
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            closeFinishedSessions();
        }
        }).detach();
}

size_t ProxyServer::getPacketsTransferred()
{
    return ProxyServer::packetsTransfered;
}

double ProxyServer::getMbsTransferred()
{
    return ProxyServer::mbTransfered;
}

size_t ProxyServer::getNumOpenSessions()
{
    std::lock_guard<std::mutex> lock(ProxyServer::_proxySessionsLock);
    return ProxyServer::_proxySessions.size();
}



void ProxyServer::closeFinishedSessions()
{
    std::lock_guard<std::mutex> lock(this->_proxySessionsLock);
    auto now = std::chrono::steady_clock::now();
    for (auto& session : this->_proxySessions)
    {
        if (!session->markedForDeletion && session->finished()) // If session is finished but not yet marked
        {
            session->markedForDeletion = true;
            session->markedTime = now;
            session->closeSockets();
            //should be fine because the sockets are closed
            //then the proxy thread should get 0 from one of its waiting recvs
            //then it will close
            {
                std::lock_guard<std::mutex> lock(this->_proxyThreadsLock);//join the thread
                if (this->_proxyThreads.count(session) > 0)
                {
                    if (this->_proxyThreads[session].joinable())
                        this->_proxyThreads[session].join();
                    this->_proxyThreads.erase(session);//remove the session
                }
                
            }
            std::cout << "Marking session " << session->getMySrcPort() << " for deletion" << std::endl;
        }
    }
    for (auto it = this->_proxySessions.begin(); it != this->_proxySessions.end(); )
    {
        ProxyHandler* temp = *it;
        if (temp->markedForDeletion && std::chrono::duration_cast<std::chrono::seconds>(now - temp->markedTime).count() >= 5)
        {
            if (temp->ipv6())
            {
                std::lock_guard<std::mutex> lock2(this->_srcPortToIpv6Lock);
                this->_srcPortToIpv6.erase(temp->getClientSrcPort());
                std::lock_guard<std::mutex> lock3(this->_ipv6PortSetLock);
                this->_ourIpv6SrcPorts.erase(temp->getMySrcPort());
            }
            else
            {
                std::lock_guard<std::mutex> lock2(this->_srcPortToIpLock);
                this->_srcPortToIp.erase(temp->getClientSrcPort());
                std::lock_guard<std::mutex> lock3(this->_portSetLock);
                this->_ourSrcPorts.erase(temp->getMySrcPort());
            }
            it = this->_proxySessions.erase(it);

            delete temp;
        }
        else
            ++it;
    }
}

bool ProxyServer::isOurPacket(const WinDivertPacket* p)
{
    const unsigned short packetSrcPort = p->getSrcPort();

    if (p->getIpv6Layer())
    {
        std::lock_guard<std::mutex> lock(this->_ipv6PortSetLock);
        return (this->_ourIpv6SrcPorts.count(packetSrcPort) > 0);
    }
    else if (p->getIpLayer())
    {
        std::lock_guard<std::mutex> lock(this->_portSetLock);
        return (this->_ourSrcPorts.count(packetSrcPort) > 0);
    }

    return false;
}

void ProxyServer::updateIpLUT(const WinDivertPacket* p)
{
    std::string dstIp = "";
    dstIp = p->getDstIp();
    const unsigned short packetSrcPort = p->getSrcPort();

    if (p->getIpLayer())
    {
        std::lock_guard<std::mutex> lock(this->_srcPortToIpLock);

        //if its not in list already, and its not ours (dst ip == src ip), and a syn packet (first ever packet)
        if (this->_srcPortToIp.find(packetSrcPort) == this->_srcPortToIp.end() &&
            (p->getIpLayer()->DstAddr != p->getIpLayer()->SrcAddr) &&
            (p->getTcpFlags().syn) && dstIp != "")
        {
            this->_srcPortToIp[packetSrcPort] = dstIp;//add listing to LUT
        }
    }
    else if (p->getIpv6Layer())
    {
        std::lock_guard<std::mutex> lock(this->_srcPortToIpv6Lock);
        const size_t IPV6_ADDR_SIZE = 16;//16 bytes
        //if its not in list already, and its not ours (dst ip == src ip), and a syn packet (first ever packet)
        //need to use memcmp instead of ==, because the address is kept as a UINT32 arr[4]
        if (this->_srcPortToIpv6.find(packetSrcPort) == this->_srcPortToIpv6.end() &&
            (memcmp(p->getIpv6Layer()->DstAddr, p->getIpv6Layer()->SrcAddr, IPV6_ADDR_SIZE)) &&
            (p->getTcpFlags().syn) && dstIp != "")
        {
            this->_srcPortToIpv6[packetSrcPort] = dstIp;//add listing to LUT
        }
    }

}




void ProxyServer::addProxySession(ProxyHandler* session) const
{
    std::lock_guard<std::mutex> lock(ProxyServer::_proxySessionsLock);
    ProxyServer::_proxySessions.insert(session);
}

ProxyHandler* ProxyServer::createNewSession(SocketCommunicator* dstServerConnection, SocketCommunicator* clientConnection, bool ipv6) const
{
    ProxyHandler* newSession = nullptr;
    if (this->_divertedPort == HTTP_PORT)
        newSession = new HTTPMITMProxy(dstServerConnection, clientConnection, ipv6);
    else if (this->_divertedPort == HTTPS_PORT)
    {
        std::string dstServer = TLSServer::getSniFromPeekClientHello(clientConnection);
        if (HTTPSMITMProxy::acceptedHost(dstServer))
        {
            std::cout << "MITMING TO " << dstServer << std::endl;
            newSession = new HTTPSMITMProxy(dstServerConnection, clientConnection, dstServer, ipv6);
        }
        else
            newSession = new HTTPSTunnelProxy(dstServerConnection, clientConnection, ipv6);
    }
    else 
        newSession = new GeneralMITMProxy(dstServerConnection, clientConnection, ipv6);

    return newSession;
}


const std::string& ProxyServer::srcPortToIp(unsigned short srcPort) const
{
    std::lock_guard<std::mutex> lock(this->_srcPortToIpLock);
    return this->_srcPortToIp[srcPort];
}
const std::string& ProxyServer::srcPortToIpv6(unsigned short srcPort) const
{
    std::lock_guard<std::mutex> lock(this->_srcPortToIpv6Lock);
    return this->_srcPortToIpv6[srcPort];
}


void ProxyServer::addPortToSet(unsigned short srcPort) const
{
    std::lock_guard<std::mutex> lock(this->_portSetLock);
    this->_ourSrcPorts.insert(srcPort);
}

void ProxyServer::addPortToSetIpv6(unsigned short srcPort) const
{
    std::lock_guard<std::mutex> lock(this->_ipv6PortSetLock);
    this->_ourIpv6SrcPorts.insert(srcPort);
}


