#include "ProxyServer.hpp"



int main()
{	
	ProxyServer ps(80);
	ps.startProxy();

	

	std::thread proxy(&ProxyServer::startProxy, &ps);

	proxy.detach();
	
	

	// get user input whether to intercept or regular proxy
	std::string s;
	std::cout << "Press to start intercerpt\n";
	std::getline(std::cin, s);

	ps.setIntercept(true);

	std::cout << "Press to stop intercerpt\n";
	std::getline(std::cin, s);
	ps.setIntercept(false);

	
	ps.stopProxy();

	return 0;
}







