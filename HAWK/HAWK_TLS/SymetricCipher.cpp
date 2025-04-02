#include "SymetricCipher.h"


void aesGcm128::createKeys(const bytes& masterSecret, const bytes& serverRandom, const bytes& clientRandom, const bool isServer)
{
	std::string label = "key expansion";
	bytes seed;
	seed.concat(serverRandom);
	seed.concat(clientRandom);
	bytes keys = prf_sha<CryptoPP::SHA256>(masterSecret, label, seed, KEY_EXPANSION_SIZE_AES_GCM_128);

	bytes writeKey1 = keys.substr(0, AES_GCM_128_KEY_SIZE);
	bytes writeKey2 = keys.substr(AES_GCM_128_KEY_SIZE, AES_GCM_128_KEY_SIZE);

	bytes writeIV1 = keys.substr(2 * AES_GCM_128_KEY_SIZE, AES_GCM_128_KEY_IV_SIZE);
	bytes writeIV2 = keys.substr(2 * AES_GCM_128_KEY_SIZE + AES_GCM_128_KEY_IV_SIZE, AES_GCM_128_KEY_IV_SIZE);

	if (isServer)
	{
		_myWriteKey = writeKey2;
		_otherWriteKey = writeKey1;

		_myIV = writeIV2;
		_otherIV = writeIV1;
	}
	else
	{
		_myWriteKey = writeKey1;
		_otherWriteKey = writeKey2;

		_myIV = writeIV1;
		_otherIV = writeIV2;
	}

	
	_myWriteKeySecBlock = bytesToSecByteBlock(_myWriteKey);
	_otherWriteKeySecBlock = bytesToSecByteBlock(_otherWriteKey);

	// Create an array of 16 zero bytes
	byte zero_bytes[16] = { 0 };

	// Create the AES encryption object in ECB mode
	CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption encryption;
	encryption.SetKey(_myWriteKeySecBlock, _myWriteKeySecBlock.size());

	// Encrypt the zero_bytes
	bytes encrypted(CryptoPP::AES::BLOCKSIZE);
	encryption.ProcessData((byte*)(&encrypted[0]), zero_bytes, sizeof(zero_bytes));

	_h_mine = Integer((CryptoPP::byte*)encrypted.data(), encrypted.size());

	encrypted.assign(CryptoPP::AES::BLOCKSIZE, '\0');

	encryption.SetKey(_otherWriteKeySecBlock, _otherWriteKeySecBlock.size());

	encryption.ProcessData((byte*)(&encrypted[0]), zero_bytes, sizeof(zero_bytes));

	_h_other = Integer((CryptoPP::byte*)encrypted.data(), encrypted.size());
}

std::vector<byte> intToBytes(uint64_t value, size_t size) {
	std::vector<byte> result(size);
	for (size_t i = 0; i < size; ++i) {
		result[size - 1 - i] = static_cast<byte>(value >> (8 * i));
	}
	return result;
}

bytes aesGcm128::encrypt(const bytes& plainText, byte contentType)
{
	bytes ivRandom;//like first python line
	generateRandom(ivRandom, 8);//turned into random
	//not constant
	bytes iv(this->_myIV);
	iv.concat(ivRandom);


	// generate AAD (added authentication data)
	// AAD = seq_num (8 bytes) + content_type (1 byte) + version (0x03, 0x03) + plaintext_size (2 bytes)
	size_t plaintext_size = plainText.size();
	std::vector<byte> aad;
	auto seq_num_bytes = intToBytes(_mySeq, 8);
	auto plaintext_size_bytes = intToBytes(plaintext_size, 2);
	aad.insert(aad.end(), seq_num_bytes.begin(), seq_num_bytes.end());
	aad.push_back(contentType);
	aad.push_back(0x03); // Version byte 1
	aad.push_back(0x03); // Version byte 2
	aad.insert(aad.end(), plaintext_size_bytes.begin(), plaintext_size_bytes.end());

	// encrypt aad using aes gcm
	std::vector<byte> ciphertext(plainText.size());
	std::vector<byte> auth_tag(AES_GCM_128_AUTH_TAG_SIZE); // AES-GCM standard tag size is 16 bytes

	try {
		GCM<AES>::Encryption encryptor;
		encryptor.SetKeyWithIV((CryptoPP::byte*)this->_myWriteKey.first(), this->_myWriteKey.size(), (CryptoPP::byte*)iv.data(), iv.size());
		AuthenticatedEncryptionFilter ef(encryptor, nullptr, false, (int)auth_tag.size());

		ef.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());  // Provide AAD
		ef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);

		ef.ChannelPut(CryptoPP::DEFAULT_CHANNEL, (CryptoPP::byte*)plainText.data(), plainText.size()); // Provide plaintext
		ef.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

		ciphertext.resize(plaintext_size);
		ef.Get(ciphertext.data(), ciphertext.size());
		auth_tag.resize(AES_GCM_128_AUTH_TAG_SIZE);
		//this auth tag is wrong, we need to calculate it later
		ef.Get(auth_tag.data(), auth_tag.size());
	}
	catch (const std::exception& e) {
		std::cerr << "Error during encryption: " << e.what() << std::endl;
		return {};
	}
	//turn ciphertext into bytes
	bytes cipherTextBytes(ciphertext.data(), ciphertext.size());
	//calculate the authentication tag, output should be 16 bytes
	bytes authTag = calcAuthTag(this->_h_mine, _mySeq, contentType, this->_myWriteKey, cipherTextBytes, iv);

	bytes output;
	output.concat(ivRandom);
	output.append((char*)ciphertext.data(), ciphertext.size());
	output.append((char*)authTag.data(), authTag.size());

	_mySeq++;

	return output;
}

bytes aesGcm128::decrypt(const bytes& cipherText, byte contentType)
{
	bytes messageRandom = cipherText.substr(0, AES_GCM_128_KEY_IV_RANDOM_SIZE);
	bytes messageAuthTag = cipherText.substr(cipherText.size() - AES_GCM_128_AUTH_TAG_SIZE, AES_GCM_128_AUTH_TAG_SIZE);
	bytes encryptedMessage = cipherText.substr(AES_GCM_128_KEY_IV_RANDOM_SIZE, cipherText.size() - AES_GCM_128_AUTH_TAG_SIZE - AES_GCM_128_KEY_IV_RANDOM_SIZE);

	bytes iv(this->_otherIV);
	iv.concat(messageRandom);

	size_t plaintext_size = encryptedMessage.size();
	std::vector<byte> aad;
	auto seq_num_bytes = intToBytes(_otherSeq, 8);
	auto plaintext_size_bytes = intToBytes(plaintext_size, 2);
	aad.insert(aad.end(), seq_num_bytes.begin(), seq_num_bytes.end());
	aad.push_back(contentType);
	aad.push_back(0x03); // Version byte 1
	aad.push_back(0x03); // Version byte 2
	aad.insert(aad.end(), plaintext_size_bytes.begin(), plaintext_size_bytes.end());

	bytes plainText;
	try {
		GCM<AES>::Decryption decryption;
		decryption.SetKeyWithIV(reinterpret_cast<const byte*>(this->_otherWriteKey.data()), this->_otherWriteKey.size(), reinterpret_cast<const byte*>(iv.data()), iv.size());

		//string sink means the output would just be redirected into it
		AuthenticatedDecryptionFilter df(decryption, new CryptoPP::StringSink(plainText), false, (int)messageAuthTag.size());
		df.ChannelPut(CryptoPP::AAD_CHANNEL, reinterpret_cast<const byte*>(aad.data()), aad.size());
		df.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
		// Provide the ciphertext
		df.ChannelPut(CryptoPP::DEFAULT_CHANNEL, reinterpret_cast<const byte*>(encryptedMessage.data()), encryptedMessage.size());
		// Provide the authentication tag
		df.ChannelPut(CryptoPP::DEFAULT_CHANNEL, reinterpret_cast<const byte*>(messageAuthTag.data()), messageAuthTag.size());
		df.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
	}
	catch (const std::exception& e) {
		std::cerr << "Error during decryption: " << e.what() << std::endl;
		return {};
	}

	_otherSeq++;

	return plainText;
}

bool aesGcm128::verifyRecordIntegrity(const bytes &encryptedBlock, const byte contentType)
{
    bytes messageRandom = encryptedBlock.substr(0, AES_GCM_128_KEY_IV_RANDOM_SIZE);
	bytes otherAuthTag = encryptedBlock.substr(encryptedBlock.size() - AES_GCM_128_AUTH_TAG_SIZE, AES_GCM_128_AUTH_TAG_SIZE);
	bytes cipherText = encryptedBlock.substr(AES_GCM_128_KEY_IV_RANDOM_SIZE, encryptedBlock.size() - AES_GCM_128_AUTH_TAG_SIZE - AES_GCM_128_KEY_IV_RANDOM_SIZE);

	bytes fullIv(this->_otherIV);
	fullIv.concat(messageRandom);

	bytes legitAuthTag = calcAuthTag(this->_h_other, _otherSeq, contentType, this->_otherWriteKey, cipherText, fullIv);
	//should work right?
	return legitAuthTag == otherAuthTag;
}

//this whole function is 1 line in python, wtf
bytes aesGcm128::calcAuthTag(Integer h_val, unsigned int seq_num, byte content_type, const bytes& write_key, const bytes& cipher_text, const bytes& iv)
{
	size_t plaintext_size = cipher_text.size();
	std::vector<byte> aad;
	auto seq_num_bytes = intToBytes(seq_num, 8);
	auto plaintext_size_bytes = intToBytes(plaintext_size, 2);
	aad.insert(aad.end(), seq_num_bytes.begin(), seq_num_bytes.end());
	aad.push_back(content_type);
	aad.push_back(0x03); // Version byte 1
	aad.push_back(0x03); // Version byte 2
	aad.insert(aad.end(), plaintext_size_bytes.begin(), plaintext_size_bytes.end());

	

	Integer hashedAad = ghash(h_val, aad.data(), aad.size(), (CryptoPP::byte*)cipher_text.data(), cipher_text.size());
	CryptoPP::SecByteBlock authTagBlock(AES_GCM_128_AUTH_TAG_SIZE);
	try {
		CryptoPP::ECB_Mode<AES>::Encryption encryption;
		encryption.SetKey((CryptoPP::byte*)write_key.data(), write_key.size());
		std::vector<byte> input_block(iv.begin(), iv.end());
		input_block.insert(input_block.end(), 3, 0x00);
		input_block.push_back(0x01); 
		std::vector<byte> ciphertext(input_block.size());
		encryption.ProcessData(ciphertext.data(), input_block.data(), input_block.size());
		Integer encrypted_result = Integer(ciphertext.data(), ciphertext.size());
		hashedAad ^= encrypted_result;
		hashedAad.Encode(authTagBlock, AES_GCM_128_AUTH_TAG_SIZE);
	}
	catch (const std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}


	bytes tag(authTagBlock.data(), authTagBlock.size());

	return tag;
}
