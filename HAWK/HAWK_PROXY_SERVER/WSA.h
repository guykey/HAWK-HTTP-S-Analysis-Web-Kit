#pragma once
#include <iostream>

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#define _WINSOCKAPI_
#include <WinSock2.h>

#pragma comment(lib,"ws2_32.lib") 
//Winsock Library
//WSA (windows socket api) needs initialization so that all the socket dlls would be linked

class WSAInitializer
{
public:
	WSAInitializer()
	{
		WSADATA wsa_data = { };
		if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
			throw std::exception("WSAStartup Failed");
	}
	~WSAInitializer()
	{
		try
		{
			WSACleanup();
		}
		catch (...) {}
	}
};