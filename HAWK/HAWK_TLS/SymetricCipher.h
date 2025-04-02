#pragma once
#include "HashFunction.h"

using CryptoPP::GCM;
using CryptoPP::AES;
using CryptoPP::ArraySink;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AutoSeededRandomPool;


class SymetricCipher
{
public:
	SymetricCipher(HashFunction* hash) : _hash(hash) { ; };

	virtual void createKeys(const bytes& masterSecret, const bytes& serverRandom, const bytes& clientRandom, const bool isServer) = 0;
	virtual bytes encrypt(const bytes& plainText, byte contentType) = 0;
	virtual bytes decrypt(const bytes& cipherText, byte contentType) = 0;

	//function that verifies the integrity of the recieved packet
	virtual bool verifyRecordIntegrity(const bytes& encryptedBlock, const byte contentType) = 0;

protected:
	bytes _myWriteKey;
	bytes _otherWriteKey;

	bytes _myIV;
	bytes _otherIV;

	bytes _myMAC;
	bytes _otherMAC;

	HashFunction* _hash;

	int _mySeq = 0;
	int _otherSeq = 0;
};


class aesGcm128 : public SymetricCipher
{
public:
	aesGcm128(HashFunction* hash) : SymetricCipher(hash) { _h_mine = 0; _h_other = 0; };

	virtual void createKeys(const bytes& masterSecret, const bytes& serverRandom, const bytes& clientRandom, const bool isServer) override;
	virtual bytes encrypt(const bytes& plainText, byte contentType) override;
	virtual bytes decrypt(const bytes& cipherText, byte contentType) override;

	virtual bool verifyRecordIntegrity(const bytes& encryptedBlock, const byte contentType);

private:

	static bytes calcAuthTag(Integer h_val, unsigned int seq_num, byte content_type, const bytes& write_key, const bytes& cipher_text, const bytes& iv);

	CryptoPP::SecByteBlock _myWriteKeySecBlock;
	CryptoPP::SecByteBlock _otherWriteKeySecBlock;

	Integer _h_mine;
	Integer _h_other;
};


#include "integer.h"

using CryptoPP::Integer;
