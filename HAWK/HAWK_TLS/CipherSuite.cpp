#include "CipherSuite.h"

CipherSuite::~CipherSuite()
{
	delete this->_asymetricCipher;
	delete this->_symetricCipher;
}

void CipherSuite::ComputeCipherSuite(word code)
{
	switch (code)
	{
	case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		_hash = sha256::getInstance();
		_asymetricCipher = new ecdhe(_isServer, _hash);
		_symetricCipher = new aesGcm128(_hash);
		
	}
}

// calls _asymetricCipher->keyExchange() and calls symetricCipher->createKeys() with the master secret
bytes CipherSuite::KeyExchange(const bytes& otherPublicKey, const bytes& clientRandom, const bytes& serverRandom)
{
	_masterSecret = _asymetricCipher->keyExchange(otherPublicKey, clientRandom, serverRandom);

	_symetricCipher->createKeys(_masterSecret, serverRandom, clientRandom, _isServer);

	return _masterSecret;
}
