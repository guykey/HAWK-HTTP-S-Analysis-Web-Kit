#include "ApplicationData.h"

ApplicationData::ApplicationData(ProxyHandler* parent, bool intercepted, APPLICATION_DATA_DIRECTION direction, APPLICATION_DATA_TYPE dataType, unsigned long long sessionId) : _parent(parent), _dataType(dataType), _intercepted(intercepted), _direction(direction), _sessionId(sessionId)
{
    this->_forward = intercepted;
    //if packet was intercepted, we need to forward it
}

ApplicationData::ApplicationData(ApplicationData& other) : _parent(other._parent), _dataType(other._dataType), _intercepted(other._intercepted), _direction(other._direction), _sessionId(other._sessionId)
{
    this->_forward = other._forward;
}


APPLICATION_DATA_TYPE ApplicationData::getDataType() const
{
    return this->_dataType;
}

const ProxyHandler* ApplicationData::getParent() const
{
    return this->_parent;
}

bool ApplicationData::intercepted() const
{
    return this->_intercepted;
}

const unsigned long long ApplicationData::getSessionId()
{
    return this->_sessionId;
}

void ApplicationData::block()
{
    this->_forward = false;
}

bool ApplicationData::forwardData() const
{
    return this->_forward;
}

APPLICATION_DATA_DIRECTION ApplicationData::getDirection()
{
    return this->_direction;
}

HTTPApplicationData::HTTPApplicationData(ProxyHandler* parent, bool intercepted, APPLICATION_DATA_DIRECTION direction, const HTTPRequest& httpRequest, unsigned long long sessionId) : ApplicationData(parent, intercepted, direction, HTTP_APPLICATION_DATA, sessionId), _original(httpRequest)
{
}



bytes& HTTPApplicationData::getRawData()
{
    return (bytes&)(this->_original.getRaw());
}

void HTTPApplicationData::setRequest(const std::string& newRequest)
{
    //if intercepted, there is no meaning to changing content
    if (!(this->_intercepted))
        return;
    //lets try this on for size
    this->_original.setRaw(newRequest);


}


HTTPRequest& HTTPApplicationData::getData()
{
    return this->_original;
}

GeneralData::GeneralData(ProxyHandler* parent, bool intercepted, APPLICATION_DATA_DIRECTION direction, const bytes& data, unsigned long long sessionId) : ApplicationData(parent, intercepted, direction, GENERAL_APPLICATION_DATA, sessionId), _original(data)
{
}

bytes& GeneralData::getRawData()
{
    return this->_original;
}

void GeneralData::setData(bytes& newData)
{
    this->_original = newData;
}



bytes& GeneralData::getData()
{
    return this->_original;
}
