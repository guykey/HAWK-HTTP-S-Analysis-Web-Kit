#pragma once
#include <iostream>
#include <vector>
#include <thread>
#include "WinDivertDev.h"


#include "../HAWK_TLS/tls.h"
#include "../HAWK_TLS/tlsServer.h"
#include "../HAWK_PROXY_SERVER/HTTP.h"
#include "../HAWK_PROXY_SERVER/HTTPSProxy.h"
#include "../HAWK_PROXY_SERVER/ProxyServer.hpp"

#include "../HAWK_PROXY_SERVER/ApplicationData.h"




class ProxyHandler
{
public:
    std::chrono::steady_clock::time_point markedTime;
    bool markedForDeletion = false;

    ProxyHandler(SocketCommunicator* dstServerConnection, SocketCommunicator* clientConnection, bool ipv6=false);
    virtual ~ProxyHandler();


    virtual void closeSockets();

    virtual void proxy();

    //the gui needs to send a packet on demand
    virtual void sendClient(const bytes& response);
    virtual void sendServer(const bytes& request);

    const unsigned long long getSessionId() const;

    
    bool finished();

    unsigned short getMySrcPort();
    unsigned short getClientSrcPort();

    inline bool setupSuccess()
    {
        return this->_setupSuccessful;
    }

    inline bool ipv6()
    {
        return this->_ipv6;
    }
protected:

    static unsigned long long nextSessionId;

    SocketCommunicator* _serverCon;
    SocketCommunicator* _clientCon;

    const unsigned short _mySrcPort;
    const unsigned short _clientSrcPort;

    bool _finished;

    const bool _ipv6;

    bool _setupSuccessful = true;


private:
    static unsigned long long _nextSessionId;
    unsigned long long generateUniqueId()
    {
        return _nextSessionId++;
    }
    const unsigned long long _sessionId;
};



class HTTPSMITMProxy : public ProxyHandler
{
public:
    HTTPSMITMProxy(SocketCommunicator* dstServerConnection, SocketCommunicator* clientConnection, const std::string& dstHost, bool ipv6=false);
    ~HTTPSMITMProxy();

    //only this class needs to override these
    virtual void sendClient(const bytes& response) override;
    virtual void sendServer(const bytes& request) override;


    static bool acceptedHost(const std::string& host);

    static bool addHost(const std::string& host);
    static void removeHost(const std::string& host);
    static std::vector<std::string> getAcceptedHosts();

    virtual void proxy() override;
protected:
    static std::mutex whiteListLock;
    static std::unordered_set<std::string> whiteList;

    TLS* _tlsClient;
    TLSServer* _tlsServer;

    std::string _dstHostname;
};

class HTTPSTunnelProxy : public ProxyHandler
{
public:
    HTTPSTunnelProxy(SocketCommunicator* serverCon, SocketCommunicator* clientCon, bool ipv6 = false);
private:
    
};

class HTTPMITMProxy : public ProxyHandler
{
public:
    HTTPMITMProxy(SocketCommunicator* dstServerConnection, SocketCommunicator* clientConnection, bool ipv6 = false);

    virtual void proxy() override;
protected:

};


class GeneralMITMProxy : public ProxyHandler
{
public:
    GeneralMITMProxy(SocketCommunicator* dstServerConnection, SocketCommunicator* clientConnection, bool ipv6 = false);
    virtual void proxy() override;

};


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






//nice code, maybe useable, we will see
//currently, deprecated





typedef std::vector<WinDivertPacket*> PacketStack;

class SessionHandler {
public:
    SessionHandler(const PacketStack& ps);
    SessionHandler();
    virtual ~SessionHandler();

    virtual void handle(WinDivertPacket* p) = 0;

    virtual PacketStack& getPackets();

    virtual PacketStack& getPending();
    virtual void clearPending();

    virtual void push_back(WinDivertPacket* p);

    virtual bool closeSession();
protected:
    PacketStack _ps;

    PacketStack _psPending;

    bool _closeSession;
};

class MitmHandler : public SessionHandler
{
public:
    MitmHandler();
    virtual ~MitmHandler();

    virtual void push_back(WinDivertPacket* p);

    virtual void handle(WinDivertPacket* p);

protected:

    void trackFinFlags(TCP_FLAGS flags);
    void accountForDelta(WinDivertPacket* p);
    bool isPacketRetransmission(WinDivertPacket* p);
    StreamCommunicator* _clientCom; // used for communicating with client TLS
    StreamCommunicator* _serverCom; // used for communicating with server TLS

    int _clientSeqDelta;
    int _clientAckDelta;

    int _serverSeqDelta;
    int _serverAckDelta;

    byte _beginHandshake;
    byte _finishHandshake;
    byte _finishHandshakeOther;

    bool _tcp;
    bool _tcpHandshakeDone;

    const byte FINISHED_FIRST_HANDSHAKE = 3;//syn + syn ack + ack
    const byte FINISHED_LAST_HANDSHAKE = 4;//fin ack + fin ack + ack + ack



};




