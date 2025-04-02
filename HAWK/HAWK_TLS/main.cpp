#include <iostream>
#include "tls.h"
#include "tlsServer.h"

int main()
{	
	try
	{
		//Certificate a("example.com_cert.der", true);
		//CertificatePrivateKey b("example.com_key.pem", true);
		//HashFunction* h = sha256::getInstance();
		//bytes s(signedData, sizeof(signedData));

		//auto sig = b.createSignature(s, h);

		//auto result = a.verifySignature(s, sig, h);

		//printf("%d\n", result);


		TLSServer tls("guthib.com_cert.der", "guthib.com_key.pem", "8582");
		tls.listen();
		std::cout << tls.recv() << "\n";
		tls.send("HTTP / 1.1 200 OK\r\nAccept - Ranges: bytes\r\nAccess - Control - Allow - Origin: *\r\nAge: 2814466\r\nCache - Control: public, max - age = 0, must - revalidate\r\nContent - Disposition: inline\r\nContent - Length: 155\r\nContent - Type: text / html; charset = utf - 8\r\nDate: Wed, 12 Feb 2025 09 : 39 : 38 GMT\r\nEtag: \"a56a8e52dfe2ed1ff2d786aed6504ce5\"\r\nLast - Modified: Fri, 10 Jan 2025 19 : 51 : 51 GMT\r\nServer: Vercel\r\nStrict - Transport - Security: max - age = 63072000\r\nX - Vercel - Cache: HIT\r\nX - Vercel - Id: fra1::rlg47 - 1739353178007 - 55f9f8754a7a\r\n\r\n");

		//TLS tls("guthib.com", "443");
		//tls.do_handshake();
		//tls.sendHttpGet();
		//bytes content = tls.recv();
		//std::cout << content << std::endl;
	}
	catch (const std::exception& e)
	{
		std::cerr << e.what() << std::endl;
	}


	return 0;
}
