#include "Certificate.h"

using CryptoPP::RSA;
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::ByteQueue;
using CryptoPP::DERSequenceEncoder;
using CryptoPP::DERSetEncoder;


Certificate::Certificate(const bytes& raw) : _raw(raw)
{
    this->extractData();
}
Certificate::Certificate(const std::string& certPath, bool isPath)
{
    _raw = getCertificate(certPath);
    this->extractData();
}
inline bool Certificate::verifySignature(const bytes& signedData, bytes& signature)
{
    return verifySignature(signedData, signature, _hash);
}

bool Certificate::verifySignature(const bytes& signedData, bytes& signature, HashFunction* hash)
{

    bytes decodedSignature;
    
    CryptoPP::RSASSA_PKCS1v15_SHA256_Verifier verifier(this->_publicKey);

    bool valid = verifier.VerifyMessage((CryptoPP::byte*)signedData.data(), signedData.size(), (const byte*)signature.data(), signature.size());

    return valid;


}

inline bytes Certificate::createSignature(const bytes& signedData)
{
    return createSignature(signedData, _hash);
}

bytes Certificate::createSignature(const bytes& signedData, HashFunction* hash)
{
    bytes signature;
    bytes signatureDataHash = hash->compute(signedData);

    Integer signatureDataInt((CryptoPP::byte*)signatureDataHash.first(), signatureDataHash.size());

    Integer& modolus = this->getN();
    Integer& exponent = this->getD();

    CryptoPP::ModularArithmetic mod(modolus);

    Integer output = mod.Exponentiate(signatureDataInt, exponent);

    size_t sizeOfOutput = output.MinEncodedSize();

    signature.resize(sizeOfOutput);

    output.Encode((CryptoPP::byte*)signature.first(), signature.size());

    return signature;
}

//using shell execute, instead of system
//btw, this is a massive security risk, as someone who's done a few pwn ctfs and stuff like that
//never do this
CertDataPaths Certificate::generateSignedCertificate(CertDataPaths caCert, const std::string& domain)
{
    CertDataPaths output;
    static const std::string outputDirectory = "temp_certificates\\";
    SHELLEXECUTEINFOA sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;  // Keep process handle
    sei.lpVerb = "open";
    sei.lpFile = "sign_certificate.exe";  // Path to the executable
    std::string args = domain + " " + caCert.certPath + " " + caCert.keyPath;
    sei.lpParameters = args.c_str();  // Arguments
    sei.nShow = SW_HIDE;  // Hide the window
    if (!ShellExecuteExA(&sei)) {
        return output;
    }
    WaitForSingleObject(sei.hProcess, INFINITE);
    DWORD exitCode;
    if (!GetExitCodeProcess(sei.hProcess, (LPDWORD) & exitCode)) {
        CloseHandle(sei.hProcess);
        return output;
    }
    CloseHandle(sei.hProcess);
    if (static_cast<int>(exitCode) == 0)
    {
        output.certPath = outputDirectory + domain + "_cert.der";
        output.keyPath = outputDirectory + domain + "_key.pem";
    }
    return output;
}



void Certificate::extractData()
{

    PCCERT_CONTEXT certContext = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, // Encoding type
        reinterpret_cast<const BYTE*>(this->_raw.data()), // Pointer to DER certificate data
        static_cast<DWORD>(this->_raw.size()) // Size of the certificate
    );

    if (!certContext)
    {
        throw std::exception("(Certificate::Certificate()): While Parsing certificate");
        return;
    }

    CHAR buffer[BUFF_SIZE] = { 0 };
    DWORD bufferSize = sizeof(buffer) / sizeof(buffer[0]);

    // Subject
    if (CertGetNameStringA(
        certContext,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        nullptr,
        buffer,
        bufferSize))
    {
        _subjectCN = bytes(buffer);
    }
    else
    {
        CertFreeCertificateContext(certContext);
        throw std::exception("(Certificate::Certificate()): While Parsing subjectCN");
    }


    // if there is public key data
    if (certContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData)
    {
        DWORD dwKeySize = certContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData;
        _rawPublicKey = bytes(certContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData, dwKeySize);
    }
    else
    {
        CertFreeCertificateContext(certContext);
        throw std::exception("(Certificate::Certificate()): While Parsing public key");
    }

    // extract signature algo
    const char* sigAlgo = certContext->pCertInfo->SignatureAlgorithm.pszObjId;

    if (sigAlgo)
    {
        _signatureAlgo = bytes(sigAlgo);
    }
    else
    {
        CertFreeCertificateContext(certContext);
        throw std::exception("(Certificate::Certificate()): While Parsing signature algorithm");
    }

    if (sigAlgo != std::string("1.2.840.113549.1.1.11")) // only support this
    {
        std::cout << "doesn't support certificate kind" << std::endl;
        std::cout << "Signature Algorithm: \"" << sigAlgo << "\" Not Supported!" << std::endl;
        std::cout << "To Add Support, Add more logic to Certificate::extractData()" << std::endl;
        return;
    }

    _hash = sha256::getInstance();

    bytes size = _raw.slice(6, 8);
    size_t sizeOfSignedData = (size_t)bytesToInt(size);

    _signedData = _raw.slice(4, 8 + sizeOfSignedData);

    _signature = _raw.slice(_raw.size() - 256, _raw.size());

    // Clean up
    CertFreeCertificateContext(certContext);


    CryptoPP::ByteQueue byteQueue;
    byteQueue.Put(reinterpret_cast<const byte*>(_rawPublicKey.data()), _rawPublicKey.size());
    byteQueue.MessageEnd();

    _publicKey.BERDecodePublicKey(byteQueue, false, 0);

    this->_d = _publicKey.GetPublicExponent();
    this->_n = _publicKey.GetModulus();
}




CertificatePrivateKey::CertificatePrivateKey(const bytes& raw) : Certificate(raw)
{
}
CertificatePrivateKey::CertificatePrivateKey(const std::string& keyPath, bool isPath)
{
    _raw = getCertificate(keyPath);
    this->extractData();
}

void CertificatePrivateKey::extractData()
{
    try {
        // Extract Base64 content by removing headers and footers
        const std::string header = "-----BEGIN RSA PRIVATE KEY-----";
        const std::string footer = "-----END RSA PRIVATE KEY-----";

        size_t start = this->_raw.find(header) + header.length();
        size_t end = this->_raw.find(footer);
        std::string base64Key = this->_raw.substr(start, end - start);

        // Remove any whitespace (important for clean decoding)
        base64Key.erase(std::remove(base64Key.begin(), base64Key.end(), '\n'), base64Key.end());
        base64Key.erase(std::remove(base64Key.begin(), base64Key.end(), '\r'), base64Key.end());

        // Decode Base64
        std::string decodedKey;
        CryptoPP::StringSource(base64Key, true,
            new CryptoPP::Base64Decoder(
                new CryptoPP::StringSink(decodedKey)
            )
        );

        CryptoPP::RSA::PrivateKey privateKey;
        CryptoPP::ByteQueue byteQueue;
        byteQueue.Put(reinterpret_cast<const byte*>(decodedKey.data()), decodedKey.size());
        byteQueue.MessageEnd();

        privateKey.BERDecodePrivateKey(byteQueue, false, 0);
        
        
        this->_d = privateKey.GetPrivateExponent();
        this->_n = privateKey.GetModulus();

        this->_privateKey = privateKey;


        _rawPublicKey = bytes(decodedKey);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

bytes CertificatePrivateKey::createSignature(const bytes& signedData)
{
    return createSignature(signedData, _hash);
}

bytes CertificatePrivateKey::createSignature(const bytes& signedData, HashFunction* hash)
{
    //bytes signature;
    bytes signatureDataHash = hash->compute(signedData);

    
    AutoSeededRandomPool rng;

    // RSA-PKCS1v1.5 Signer with SHA-256
    CryptoPP::RSASSA_PKCS1v15_SHA256_Signer signer(_privateKey);

    // Generate the signature
    size_t sigLen = signer.MaxSignatureLength();
    CryptoPP::SecByteBlock signature(sigLen);

    sigLen = signer.SignMessage(rng, (CryptoPP::byte*)signedData.data(), signedData.size(), signature);
    signature.resize(sigLen); // Adjust size

    this->_signature = bytes(signature.data(), signature.size());

    //PrintHexStr("kaka ", this->_signature);

    return this->_signature;
    

    
}

std::ostream& operator<<(std::ostream& os, const Certificate& c)
{
    os << "subjectCN: " << c._subjectCN <<
        "\nsignature algo: " << c._signatureAlgo <<
        "\n";
    
    PrintHexStr(os, "Signed data: ", c._signedData);
    PrintHexStr(os, "Public Key: ", c._rawPublicKey);

    os << "n: " << c._n <<
        "\nd: " << c._d << "\n";
}

bool verifyChainOfTrust(std::vector<Certificate*>& certs, const std::string& domain)
{
    bool chain = true;

    for (int i = 0; i < certs.size(); i++)
    {
        if (i == 0)
        {
            auto cn = certs[i]->getSubjectCN();

            if (cn == domain)
            {
                std::cout << "Domain name is OK\n";
            }
            else
            {
                std::cout << "WARNING: wrong domain: " << cn << " != " << domain << "\n";
            }
        }

        if (i < certs.size() - 1)
        {
            auto a = certs[i]->getSignature();
            chain = chain and certs[i + 1]->verifySignature(certs[i]->getSignedData(), a);
        }
        else // root CA check
        {
            ;
        }
    }

    return chain;
}

const bytes getCertificate(const std::string& certPath)
{
    bytes raw;

    std::streamsize certLength = 0;
    std::ifstream certFile;
    certFile.open(certPath.c_str(), std::ios::in | std::ios::binary);
    if (!certFile.is_open())
    {
        std::string errMessage = "Error Reading Certificate File With Path: \"";
        errMessage += certPath;
        errMessage += '\"';
        throw std::exception(errMessage.c_str());
    }

    certFile.seekg(0, std::ios::end);//get the file length
    certLength = certFile.tellg();
    certFile.seekg(0, std::ios::beg);


    raw.resize(certLength);//resize to fit

    certFile.read((char*)raw.first(), raw.size());//read into buffer
    return raw;
}

void createCertificate(const std::string& caCertPath, const std::string& caKeyPath, const std::string& subjectName)
{
    // Open a cryptographic provider
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
    {
        if (GetLastError() == NTE_EXISTS) {
            CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, 0);
        }
    }

    if (!hProv) {
        std::cerr << "Error acquiring cryptographic context: " << GetLastError() << std::endl;
        return;
    }

    // Generate a key pair
    HCRYPTKEY hKey = 0;
    if (!CryptGenKey(hProv, AT_SIGNATURE, 0, &hKey)) {
        std::cerr << "Error generating key: " << GetLastError() << std::endl;
        CryptReleaseContext(hProv, 0);
        return;
    }

    // Define the subject name
    CERT_NAME_BLOB SubjectIssuerBlob = {};
    if (!CertStrToNameA(X509_ASN_ENCODING, subjectName.c_str(), CERT_X500_NAME_STR, NULL, NULL, &SubjectIssuerBlob.cbData, NULL)) {
        std::cerr << "Error formatting subject name" << std::endl;
        return;
    }

    BYTE* pbEncodedName = new BYTE[SubjectIssuerBlob.cbData];
    SubjectIssuerBlob.pbData = pbEncodedName;
    if (!CertStrToNameA(X509_ASN_ENCODING, subjectName.c_str(), CERT_X500_NAME_STR, NULL, SubjectIssuerBlob.pbData, &SubjectIssuerBlob.cbData, NULL)) {
        std::cerr << "Error encoding subject name" << std::endl;
        delete[] pbEncodedName;
    }

    // Create the self-signed certificate
    PCCERT_CONTEXT pCertContext = CertCreateSelfSignCertificate(hProv, &SubjectIssuerBlob, 0, NULL, NULL, NULL, NULL, NULL);
    if (!pCertContext) {
        std::cerr << "Error creating certificate: " << GetLastError() << std::endl;
        delete[] pbEncodedName;
        return;
    }

    std::cout << "Certificate created successfully!" << std::endl;

    // Cleanup
    CertFreeCertificateContext(pCertContext);
    delete[] pbEncodedName;
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
}



