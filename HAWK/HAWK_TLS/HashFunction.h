#pragma once
#include "constants.hpp"


class HashFunction
{
public:
	HashFunction() { _outputSize = 0; };
	
	virtual const bytes compute(const bytes& input) = 0;
	size_t getSize() { return _outputSize; };

protected:
	size_t _outputSize;
};



class sha1 : public HashFunction
{
public:
	sha1() { _outputSize = SHA1_OUTPUT_SIZE; }
	~sha1() { delete _instance; }

	virtual const bytes compute(const bytes& input) override;

	static HashFunction* getInstance() { if (!_instance) _instance = new sha1; return _instance; }

private:
	static HashFunction* _instance;
};

class sha224 : public HashFunction
{
public:
	sha224() { _outputSize = SHA_224_OUTPUT_SIZE; }
	~sha224() { delete _instance; }

	virtual const bytes compute(const bytes& input) override;

	static HashFunction* getInstance() { if (!_instance) _instance = new sha224; return _instance; }

private:
	static HashFunction* _instance;
};

class sha256 : public HashFunction
{
public:
	sha256() { _outputSize = SHA_256_OUTPUT_SIZE; }
	~sha256() { delete _instance; }

	virtual const bytes compute(const bytes& input) override;

	static HashFunction* getInstance() { if (!_instance) _instance = new sha256; return _instance; }

private:
	static HashFunction* _instance;
};

class sha384 : public HashFunction
{
public:
	sha384() { _outputSize = SHA_384_OUTPUT_SIZE; }
	~sha384() { delete _instance; }

	virtual const bytes compute(const bytes& input) override;

	static HashFunction* getInstance() { if (!_instance) _instance = new sha384; return _instance; }

private:
	static HashFunction* _instance;
};

class sha512 : public HashFunction
{
public:
	sha512() { _outputSize = SHA_512_OUTPUT_SIZE; }
	~sha512() { delete _instance; }

	virtual const bytes compute(const bytes& input) override;

	static HashFunction* getInstance() { if (!_instance) _instance = new sha512; return _instance; }

private:
	static HashFunction* _instance;
};
