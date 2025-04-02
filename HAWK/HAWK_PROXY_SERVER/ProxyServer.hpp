#pragma once

#include <unordered_map>
#include <vector>
#include <thread>
#include <chrono>
#include <mutex>
#include <unordered_set>

#include <queue>
#include <atomic>
#include <condition_variable>



#include "../HAWK_PROXY_SERVER/WinDivertDev.h"
#include "../HAWK_PROXY_SERVER/SessionHandlers.h"

#include "../HAWK_PROXY_SERVER/ApplicationData.h"


/*
Split to 2 main components


                Proxy Server
        ----------------------------
        |                           |
        |                           |
        |                           |
    WinDivert                Socket Handler


    Windivert:  diverts the packets to our own local server,
                it "reroutes" the packets to our own ip at a certain port (8583 or 8584)
                it makes an exception for packets that come from us, from our own client
                it does that by maintaining a set of ports that are ours, those packets won't be diverted
                the filter needs to be dstPort == <port to block> and srcPort == <our servers port>
                when the dst port is port to block, we either divert it (change the dst ip and port), or let it go (if the src port is our own port)
                when the src port is our servers port, we need to always "impersonate" it, change the src ip and port to be the original dst and ip
                so that the original clients connection won't break (if we hand't done that, the original client would have sent syn to 192.168.0.1 and gotten syn ack from 10.0.0.6)
                in brief, it moves packets to our own socket and allows our own connections to work

    Socket Handler: a simple listening socket, that gets connections and it handles it, this handler works the same
                    as the handler that exists in HTTPSProxy, it just gets socket connections!
                    so it will be really really easy to switch to just using windivert, without needing to change much.
                    so using windivert, we were able to replicate the work of the registry
                    the registry works because google chrome sees that windows set a proxy, and it blocks the requests
                    but google can choose to not allow that and then it woulnd't work
                    but windivert uses wfp (windows filtering platform), and chrome cant change that
                    in this case, google chrome doesn't know its being diverted
                    (it could know that because packets would come in an instant)

    in short, the socket handler is nothing special, its like the one in HTTPSProxy.h
    it just doens't get CONNECT requests
    we would have to extract the dst server (needed for connection and generating the certificate) from the sni in the original client's client hello




*/




#define PROXY_PORT 80   


#define PROXY_SERVER_PORT 8583
//if user wants to proxy port 8583, we cant use it as our proxy server port
//so we have an alternate one
//8583 is the number after 8582, the port for the https registry listening server
#define ALTERNATE_PROXY_SERVER_PORT 8584

enum MITM_CONNECTION {HTTPS_MITM=0, HTTP_MITM, GENERAL_MITM, NON_MITM};


//really good for gui-backend communication

template <typename T>
class LockFreeQueue {
public:
    LockFreeQueue() = default;
    void push(T* item) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.push(item);
        }
        has_data_.store(true, std::memory_order_release);
        cv_.notify_one();  // Notify waiting thread
    }

    T* pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        // Wait for data or the queue to be closed
        cv_.wait(lock, [this] { return !queue_.empty() || closed_; });

        if (queue_.empty()) {
            return nullptr;  // Return nullptr if the queue is closed and empty
        }

        T* item = queue_.front();
        queue_.pop();

        if (queue_.empty()) {
            has_data_.store(false, std::memory_order_release);
        }

        return item;
    }

    bool hasData() {
        return has_data_.load(std::memory_order_acquire);
    }


    // Close the queue and notify all waiting threads
    void close() {
        std::lock_guard<std::mutex> lock(mutex_);
        closed_ = true;

        clearQueue();
        cv_.notify_all();  // Notify all waiters that the queue is closed
    }

    // Check if the queue is closed
    bool isClosed() {
        return closed_;
    }


    void reopen() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!closed_) {
            return;  // Queue is already open, no action needed
        }

        closed_ = false;
        clearQueue();
        has_data_.store(false, std::memory_order_release);
        cv_.notify_all();  // Notify waiters that the queue is open again
    }

private:

    void clearQueue() {
        // Free the memory of all remaining items in the queue before reopening
        while (!queue_.empty()) {
            T* item = queue_.front();
            queue_.pop();
            delete item;  // Free the memory
        }
    }

    std::queue<T*> queue_;
    std::atomic<bool> has_data_{ false };
    std::atomic<bool> closed_{ false };
    std::mutex mutex_;
    std::condition_variable cv_;
};

//forward decleration
class ApplicationData;
class ProxyHandler;
class ProxyServer
{
public:
    ProxyServer(unsigned short port);
    ~ProxyServer();

    void startProxy();
    void stopProxy();
    static void toggleIntercept();
    static void closeIntercept();

    static bool intercept();

    static std::string _myIp;
    static std::string _myIpv6;

    static unsigned short getListeningPort();

    //only called by gui
    static ApplicationData* pullAppData();
    //only called by ProxyHandlers
    static void pushAppData(ApplicationData* appData);

    static void halt();

    

    //this gets application data, gets the parent from it
    //if the parent still exists, we send the data to it, and it does whatever it wants with it
    //has to be static
    static void forwardAppData(ApplicationData* appData);

    const static bool ipv6Available;
    const static bool ipv4Available;


    static size_t getPacketsTransferred();
    static double getMbsTransferred();
    static size_t getNumOpenSessions();


private:
    void startCleanupThread();
    

    void acceptNewClients() const;
    void acceptNewIpv6Clients() const;


    const std::string& srcPortToIp(unsigned short srcPort) const;
    const std::string& srcPortToIpv6(unsigned short srcPort) const;

    void addPortToSet(unsigned short srcPort) const;
    void addPortToSetIpv6(unsigned short srcPort) const;
    void addProxySession(ProxyHandler* session) const;

    ProxyHandler* createNewSession(SocketCommunicator* dstServerConnection, SocketCommunicator* clientConnection, bool ipv6=false) const;


    void closeFinishedSessions();

    bool isOurPacket(const WinDivertPacket* p);

    void updateIpLUT(const WinDivertPacket* p);


    WinDivertDev _wd;

    bool _runProxy;
    static bool _intercept;

    bool _listening = true;

    mutable SocketCommunicator* _listeningSocket = nullptr;
    mutable SocketCommunicator* _ipv6ListeningSocket = nullptr;

    //sockets that got accepted by listening socket (where trying to connect to 127.0.0.1:8583)
    //and their src port as the
    mutable std::unordered_map<unsigned short, std::string> _srcPortToIp;
    mutable std::unordered_set<unsigned short> _ourSrcPorts;
    mutable std::mutex _portSetLock;
    mutable std::mutex _srcPortToIpLock;

    //additional ipv6 data, needed because they don't rely on one another

    mutable std::unordered_map<unsigned short, std::string> _srcPortToIpv6;
    mutable std::unordered_set<unsigned short> _ourIpv6SrcPorts;
    mutable std::mutex _ipv6PortSetLock;
    mutable std::mutex _srcPortToIpv6Lock;

    static std::mutex _proxySessionsLock;
    static std::unordered_set<ProxyHandler*> _proxySessions;
    static std::mutex _proxyThreadsLock;
    static std::unordered_map<ProxyHandler*, std::thread> _proxyThreads;


    static LockFreeQueue<ApplicationData> _pendingData;


    std::thread* _listeningThread;
    std::thread* _ipv6ListeningThread;

    static unsigned short _listeningPort;//
    const unsigned short _divertedPort;//port to block/divert

    static size_t packetsTransfered;
    static double mbTransfered;
};






