#pragma once
#include "AsymetricCipher.h"
#include "SymetricCipher.h"
#include "HashFunction.h"


class CipherSuite
{
public:
	CipherSuite(bool isServer) { _code = 0; _isServer = isServer; }

	~CipherSuite();

	void ComputeCipherSuite(word code);
	bytes KeyExchange(const bytes& otherPublicKey, const bytes& clientRandom, const bytes& serverRandom); // calls _asymetricCipher->keyExchange() and calls symetricCipher->createKeys() with the master secret

	SymetricCipher* getSymetric() { return _symetricCipher; }
	HashFunction* getHash() { return _hash; }
	AsymetricCipher* getAsymetric() { return _asymetricCipher; }

	const bytes getMasterSecret() const { return _masterSecret; }
	static bytes getSupportedCipherSuites()
	{
		bytes cipherSuites;

		cipherSuites.push(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, sizeof(word));

		return cipherSuites;
	}
	
private:
	word _code;

	bytes _masterSecret;
	AsymetricCipher* _asymetricCipher=nullptr;
	SymetricCipher* _symetricCipher=nullptr;
	
	HashFunction* _hash=nullptr;
	bool _isServer;
};
