#pragma once
#include "constants.hpp"
#include "base64.h"
#include "rsa.h"
#include "cryptlib.h"
#include <wincrypt.h>
#include "HashFunction.h"


using CryptoPP::Integer;

typedef struct {
	std::string certPath;
	std::string keyPath;
} CertDataPaths;


class Certificate
{
public:
	Certificate() {}
	Certificate(const bytes& raw);
	Certificate(const std::string& certPath, bool isPath);
	~Certificate() {};

	const bytes getRaw() const { return _raw; }
	Integer& getD() { return this->_d; }
	Integer& getN() { return this->_n; }

	const bytes getSubjectCN() const { return _subjectCN; }
	const bytes getSignedData() const { return _signedData; }
	const bytes getSignature() const { return _signature; }

	virtual bool verifySignature(const bytes& signedData, bytes& signature);
	virtual bool verifySignature(const bytes& signedData, bytes& signature, HashFunction* hash);
	virtual bytes createSignature(const bytes& signedData);
	virtual bytes createSignature(const bytes& signedData, HashFunction* hash);

	//static CertDataPaths generateCertificate(const std::string& certUrl, const std::string& trustedCACertPath, const std::string& trustedCAKeyPath);
	//static void addCAToTrustedRoot();

	static CertDataPaths generateSignedCertificate(CertDataPaths caCert, const std::string& domain);

	friend std::ostream& operator<<(std::ostream& os, const Certificate& c);

protected:
	virtual void extractData();
	
	bytes _raw;
	bytes _subjectCN;
	bytes _rawPublicKey;
	bytes _signatureAlgo;
	bytes _signature;
	bytes _signedData;

	CryptoPP::RSA::PublicKey _publicKey;


	Integer _n;
	Integer _d;

	HashFunction* _hash=nullptr;
};


class CertificatePrivateKey : public Certificate
{
public:
	CertificatePrivateKey(const bytes& raw);
	CertificatePrivateKey(const std::string& keyPath, bool isPath);

	virtual bytes createSignature(const bytes& signedData) override;
	virtual bytes createSignature(const bytes& signedData, HashFunction* hash) override;

private:

	virtual void extractData() override;

	CryptoPP::RSA::PrivateKey _privateKey;
};


bool verifyChainOfTrust(std::vector<Certificate*>& certs, const std::string& domain);
const bytes getCertificate(const std::string& certPath);


void createCertificate(const std::string& caCertPath, const std::string& caKeyPath, const std::string& subjectName);
