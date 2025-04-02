#pragma once
#include "HashFunction.h"


using CryptoPP::ECIES;
using CryptoPP::ECP;
using CryptoPP::SecByteBlock;


class AsymetricCipher
{
public:
	AsymetricCipher(bool isServer, HashFunction* hash) : _hash(hash), _privateKey((size_t)MAX_KEY_SIZE), _publicKey((size_t)MAX_KEY_SIZE) { ; };

	virtual bytes keyExchange(const bytes& otherPublicKey, const bytes& clientRandom, const bytes& serverRandom) = 0; // returns master secret

	bytes getRawPrivateKey() const
	{
		return _privateKey;
	}
	bytes getRawPublicKey() const
	{
		return _publicKey;
	}

protected:
	bytes _privateKey;
	bytes _publicKey;

	HashFunction* _hash;
};


class ecdhe : public AsymetricCipher
{
public:
	ecdhe(bool isServer, HashFunction* hash);
	virtual bytes keyExchange(const bytes& otherPublicKey, const bytes& clientRandom, const bytes& serverRandom) override; // returns master secret



private:
	bytes calculateMasterSecret(const bytes& clientRandom, const bytes& serverRandom);


	ECIES<ECP>::PrivateKey _privateKeyInstance;
	ECIES<ECP>::PublicKey _publicKeyInstance;

	SecByteBlock _privateKeyByteBlock;
	SecByteBlock _publicKeyByteBlock;


	bytes _preMasterSecret;

	bytes _masterSecret;

	CryptoPP::OID _curve;
};
