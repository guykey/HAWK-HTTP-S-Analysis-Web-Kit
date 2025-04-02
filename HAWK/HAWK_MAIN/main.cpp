
/* ****************************************************************************
      _____  ______          _____    _______ _    _ _____  _____ 
     |  __ \|  ____|   /\   |  __ \  |__   __| |  | |_   _|/ ____|
     | |__) | |__     /  \  | |  | |    | |  | |__| | | | | (___  
     |  _  /|  __|   / /\ \ | |  | |    | |  |  __  | | |  \___ \ 
     | | \ \| |____ / ____ \| |__| |    | |  | |  | |_| |_ ____) |
     |_|  \_\______/_/    \_\_____/     |_|  |_|  |_|_____|_____/ 

     if you try to run this code, you might run into error: unresolved symbol WinMain
     that is because your configuration is for no console apps, if you try to run console app
     you need console configuration. go to Linker > System

*///***************************************************************************



////PROXY SERVER MAIN TEST
//#include "../HAWK_PROXY_SERVER/HTTPSProxy.h"
//#include <iostream>
//#include "../HAWK_PROXY_SERVER/ProxyServer.hpp"
//int main()
//{
//
//	try
//	{
//		ProxyServer ps(80);
//		ps.startProxy();
//	}
//	catch (const std::exception& e)
//	{
//		std::cout << e.what() << std::endl;
//	}
//	
//	//std::thread proxy(&ProxyServer::startProxy, &ps);
//
//	//proxy.join();
//
//	//RegistryWriter::revertChanges();
//	//return 0;
//
//	//HTTPSProxyServer ps;
//
//	//ps.proxy(HTTP_PROXY | HTTPS_PROXY);
//
//
//
//	return 0;
//}


////PACKET CAPTURE MAIN TEST
//#include "../HAWK_WIRESHARK/PacketCapture.h"
//int main()
//{
//    PacketCapture c;
//
//    c.listen();
//}

////HAWK TLS MAIN TEST
//#include "../HAWK_TLS/tls.h"
//#include "../HAWK_TLS/tlsServer.h"
//
//int main()
//{
//	try
//	{
//		//Certificate a("example.com_cert.der", true);
//		//CertificatePrivateKey b("example.com_key.pem", true);
//		//HashFunction* h = sha256::getInstance();
//		//bytes s(signedData, sizeof(signedData));
//
//		//auto sig = b.createSignature(s, h);
//
//		//auto result = a.verifySignature(s, sig, h);
//
//		//printf("%d\n", result);
//
//		//both below sholdn't work, because the sockets aren't being made in tls.listen and tls.do_handshake
//		// 
//		//TLSServer tls("guthib.com_cert.der", "guthib.com_key.pem", "8582");
//		//tls.listen();
//		//std::cout << tls.recv() << "\n";
//		//tls.send("HTTP / 1.1 200 OK\r\nAccept - Ranges: bytes\r\nAccess - Control - Allow - Origin: *\r\nAge: 2814466\r\nCache - Control: public, max - age = 0, must - revalidate\r\nContent - Disposition: inline\r\nContent - Length: 155\r\nContent - Type: text / html; charset = utf - 8\r\nDate: Wed, 12 Feb 2025 09 : 39 : 38 GMT\r\nEtag: \"a56a8e52dfe2ed1ff2d786aed6504ce5\"\r\nLast - Modified: Fri, 10 Jan 2025 19 : 51 : 51 GMT\r\nServer: Vercel\r\nStrict - Transport - Security: max - age = 63072000\r\nX - Vercel - Cache: HIT\r\nX - Vercel - Id: fra1::rlg47 - 1739353178007 - 55f9f8754a7a\r\n\r\n");
//
//		TLS tls("guthib.com", "443");
//		tls.do_handshake();
//		tls.sendHttpGet();
//		bytes content = tls.recv();
//		std::cout << content << std::endl;
//	}
//	catch (const std::exception& e)
//	{
//		std::cerr << e.what() << std::endl;
//	}
//
//
//	return 0;
//}


//gzip test
//#include <iostream>
//#include "../HAWK_PROXY_SERVER/HTTP.h"
//
//int main()
//{
//    bytes source("hello this is source text");
//    bytes compressed;
//    ZlibCompression::compressData(source, compressed);
//
//    PrintHexStr("Compressed", compressed);
//
//    bytes uncompressed;
//    ZlibCompression::decompressData(compressed, uncompressed);
//
//    std::cout << uncompressed << std::endl;
//}





////HAWK GUI MAIN TEST
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include "../HAWK_GUI/MainWindow.h"
#include "../HAWK_WIRESHARK/ProtocolDB.h"
//redirect the cout to log file, so no problems

std::ofstream logFile("proxy_log.txt");
std::streambuf* coutBuf = std::cout.rdbuf(logFile.rdbuf());




wxIMPLEMENT_APP(HawkApp);