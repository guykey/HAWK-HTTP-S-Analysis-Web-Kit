#pragma once
#include "../HAWK_PROXY_SERVER/ProxyServer.hpp"

enum APPLICATION_DATA_TYPE { HTTP_APPLICATION_DATA = 0, GENERAL_APPLICATION_DATA };
enum APPLICATION_DATA_DIRECTION {TO_CLIENT=0, TO_SERVER};

//forward decleration
class ProxyHandler;
class ApplicationData
{
public:

	APPLICATION_DATA_TYPE getDataType() const;


	const ProxyHandler* getParent() const;//dangerous

	bool intercepted() const;

	const unsigned long long getSessionId();

	void block();
	bool forwardData() const;

	virtual bytes& getRawData() = 0;


	APPLICATION_DATA_DIRECTION getDirection();

protected:
	//protected ctor, cant make instance of Application Data, and its not really
	//and abstract class, so i need this
	//second thought, we need getRawData (used by ProxyServer on data's way back)
	//but still, make it protected

	ApplicationData(ProxyHandler* parent, bool intercepted, APPLICATION_DATA_DIRECTION direction, APPLICATION_DATA_TYPE dataType, unsigned long long sessionId);
	ApplicationData(ApplicationData& other);

	const APPLICATION_DATA_TYPE _dataType;
	const ProxyHandler* _parent;
	const bool _intercepted;
	const APPLICATION_DATA_DIRECTION _direction;
	const unsigned long long _sessionId;
private:
	bool _forward;
};


class HTTPApplicationData : public ApplicationData
{
public:
	HTTPApplicationData(ProxyHandler* parent, bool intercepted, APPLICATION_DATA_DIRECTION direction, const HTTPRequest& httpRequest, unsigned long long sessionId);
	virtual bytes& getRawData() override;

	void setRequest(const std::string& newRequest);
	
	HTTPRequest& getData();
private:
	HTTPRequest _original;
};


class GeneralData : public ApplicationData
{
public:
	GeneralData(ProxyHandler* parent, bool intercepted, APPLICATION_DATA_DIRECTION direction, const bytes& data, unsigned long long sessionId);
	virtual bytes& getRawData() override;
	void setData(bytes& newData);

	bytes& getData();
private:
	bytes _original;
};

