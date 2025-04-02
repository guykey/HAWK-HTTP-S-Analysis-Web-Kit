#pragma once
#include "../HAWK_WIRESHARK/ProtocolDB.h"
#include "../HAWK_PROXY_SERVER/WSA.h"
#include <ws2tcpip.h>

#include <type_traits>

#include <vector>
#include <string>
#include <iostream>
#include <random>
#include <windows.h>
#include <wincrypt.h>

#include "cryptlib.h"
#include "secblock.h"
#include "hex.h"
#include "hmac.h"
#include "files.h"
#include "sha.h"
#include "integer.h"
#include "aes.h"
#include "modes.h"
#include "gcm.h"
#include "osrng.h"
#include "eccrypto.h"
#include "oids.h"


#pragma comment(lib, "crypt32.lib")


#define NULL_KEY {}

typedef unsigned char byte;

typedef struct
{
	byte R;
	byte G;
	byte B;
}RGBColour;


#define MAX_KEY_SIZE 65
#define BYTE_SIZE 8
#define BUFF_SIZE 256



class bytes : public std::string
{
public:
	bytes(size_t size) : std::string(size, '\0') {}
	bytes() : std::string() {}
	bytes(byte* arr) : std::string((char*)arr) {}
	bytes(byte* arr, size_t size) : std::string((char*)arr, size) {}
	bytes(const std::string& str) : std::string(str) {}
	bytes(const bytes& b) : std::string(b) {}


	void push(const bytes& other) { this->insert(this->begin(), other.begin(), other.end()); }
	void push(const unsigned char num) { this->insert(this->begin(), num); }
	void push(const unsigned long long num, size_t size) // size is in bytes
	{
		byte* a = (byte*) & num;
		size = (((size) < (sizeof(unsigned long long))) ? (size) : (sizeof(unsigned long long)));

		for (int i = 0; i < size; i++)
		{
			this->push(a[i]);
		}
	}

	bytes slice(size_t start, size_t end) const
	{ 
		if (end - start > this->size())
			throw std::exception(__FUNCTION__ " - Invalid Arguments Given!");
		return bytes(substr(start, end - start));
	}

	void concat(const bytes& other) {
		this->append(other.data(), other.size());
	}
	void concat(const unsigned char num) { this->push_back(num); }
	void concat(const unsigned long long num, size_t size)
	{
		byte* a = (byte*)&num;
		size = (((size) < (sizeof(unsigned long long))) ? (size) : (sizeof(unsigned long long)));

		for (size_t i = size - 1; i >= 0; i--)
		{
			this->concat(a[i]);
		}
	}

	//useless, use == operator
	//bool isEqual(const bytes& other);

	bytes& operator=(const bytes& other) { std::string::operator=(other); return *this; }
	char* operator&() { return &((*this)[0]); }  //get the address of the first byte
	byte* first() { return (byte*)(&((*this)[0])); }//add a method because operator sucks
};


class bytesStream : public bytes
{
public:
	bytesStream() : bytes() {}
	bytesStream(size_t size) : bytes(size) {}
	bytesStream(const bytes& b) : bytes(b) {}
	bytesStream(byte* arr, size_t size) : bytes(arr, size) {}
	bytesStream(byte* arr) : bytes(arr) {}
	bytesStream(const std::string& str) : bytes(str) {}

	bytesStream& operator<<(const bytes& b); // write to stream
	bytesStream& operator<<(const std::string& b); // write to stream
	bytesStream& operator<<(const char* b); // write to stream
	bytesStream& operator>>(bytes& b); // read from stream, bytes object should
	// be in size of the amount of bytes that you want to read

	int read(bytes& buffer, size_t size);
	int write(const bytes& buffer, size_t size);


	friend std::ostream& operator<<(std::ostream& os, const bytesStream& bs); // write to stream

private:

};

//templated function, gets HashFunction as input
//HashFunction is the type of hash we want to use for this function
//we use enable_if to make it so this function could only
//get template types that are either SHA256 or SHA384 we could add ones
// otherwise it won't compile, which would save us the trouble of debugging why the code crashes
template<typename HashFunction>
typename std::enable_if<
	std::is_same<HashFunction, CryptoPP::SHA256>::value ||
	std::is_same<HashFunction, CryptoPP::SHA384>::value,
	bytes
>::type
hmacSha(const bytes& key, const std::string& message)
{
	try {
		// Create an HMAC object using SHA256
		CryptoPP::HMAC<HashFunction> hmac((const byte*)key.data(), key.size());

		// Compute the HMAC digest
		std::string digest;
		CryptoPP::StringSource ss(message, true,
			new CryptoPP::HashFilter(hmac,
				new CryptoPP::StringSink(digest) // Directly store binary output
			)
		);

		return bytes(digest); // Binary output
	}
	catch (const CryptoPP::Exception& e) {
		std::cerr << "Crypto++ exception: " << e.what() << std::endl;
		return bytes();
	}
}

template<typename HashFunction>
typename std::enable_if<
	std::is_same<HashFunction, CryptoPP::SHA256>::value ||
	std::is_same<HashFunction, CryptoPP::SHA384>::value,
	bytes
>::type
prf_sha(const bytes& secret, const std::string& label, const std::string& seed, size_t length)
{
	std::string A = label + seed;
	bytes result;
	result.reserve(length);

	while (result.size() < length)
	{
		A = hmacSha<HashFunction>(secret, A);

		result += hmacSha<HashFunction>(secret, A + label + seed);
	}

	return result.substr(0, length);
}


enum ALGORITHMS_DICT {
	SHA1 = 2, SHA224, SHA256, SHA384, SHA512
};

void PrintHex(const std::string& label, const CryptoPP::SecByteBlock& data);
void PrintHexStr(const std::string& label, const bytes& data);
void PrintHexStr(std::ostream& os, const std::string& label, const bytes& data);

using CryptoPP::Integer;

Integer gf_mult(const Integer& x, const Integer& y);
Integer h_mult(const Integer& h, Integer val);
void nb_to_n_bytes(uint64_t value, size_t len, byte* out);
Integer ghash(const Integer& h, const byte* a, size_t a_len, const byte* c, size_t c_len);

unsigned long long bytesToInt(bytes& data);
unsigned long long bytesToInt(bytes& data, size_t start, size_t end);

inline void generateRandom(bytes& output, const int numBytes)
{
	output.clear();//clear vector
	output.reserve(numBytes);//reserve the size
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, 255);
	int i = 0;
	for (i = 0; i < numBytes; i++)
		output.push_back((unsigned char)dis(gen));
}


inline CryptoPP::SecByteBlock bytesToSecByteBlock(bytes& byt)
{
	CryptoPP::SecByteBlock a(reinterpret_cast<const unsigned char*>(byt.data()), byt.size());

	return a;
}


typedef unsigned short word;

//tls 1.2
#define TLS_VERSION (word)0x0303

//Hanshake types
#define CLIENT_HELLO_HANDSHAKE_TYPE 0x01
#define SERVER_HELLO_HANDSHAKE_TYPE 0x02
#define CERTIFICATE_HANDSHAKE_TYPE 0x0b
#define SERVER_KEY_EXCHANGE_HANDSHAKE_TYPE 0x0c
#define SERVER_HELLO_DONE_HANDSHAKE_TYPE 0x0e
#define CLIENT_KEY_EXCHANGE_HANDSHAKE_TYPE 0x10

#define CHANGE_CIPHER_SPEC_CONTENT 0x01

#define SHA1_OUTPUT_SIZE 20
#define SHA_224_OUTPUT_SIZE 28
#define SHA_384_OUTPUT_SIZE 48
#define SHA_256_OUTPUT_SIZE 32
#define SHA_512_OUTPUT_SIZE 64


// content types
#define TLS_APPLICATION_DATA 23
#define TLS_HANDSHAKE 22
#define CHANGE_CIPHER_SPEC 20
#define TLS_HEADER_SIZE 5

// sizes
#define PRE_MASTER_SECRET_SIZE 32
#define MASTER_SECRET_SIZE 48

#define KEY_EXPANSION_SIZE_AES_GCM_128 40
#define AES_GCM_128_KEY_SIZE 16
#define AES_GCM_128_KEY_IV_SIZE 4
#define AES_GCM_128_KEY_IV_RANDOM_SIZE 8

#define AES_GCM_128_AUTH_TAG_SIZE 16
#define AES_GCM_128_BLOCK_SIZE 16


#define RANDOM_STREAM_SIZE 32
#define SESSION_ID_SIZE 32
#define CONTENT_LENGTH_SIZE 3

#define VERIFY_DATA_LENGTH_AES_GCM_128 12
#define CLIENT_FINISHED_PRF_SEED "client finished"



// CIPHER SUITE
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 0xc02f

#define SERVER_NAME_INDEX_EXTENSION_TYPE 0x0000

#define RENEGOTIATION_INFO_EXTENSION_TYPE 0xff01
#define ELIPTIC_CURVE_POINT_FORMATS_EXTENSION_TYPE 0x000b
#define SESSION_TICKET_EXTENSION_TYPE 0x0023


#define SECP251R1_CURVE 0x0017
#define NAMED_CURVE 0x03

#define RSA_PKCS1_SHA256_SIGNATURE_ALGORITHM 0x0401



