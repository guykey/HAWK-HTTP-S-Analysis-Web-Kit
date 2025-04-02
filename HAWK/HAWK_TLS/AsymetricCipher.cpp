#include "AsymetricCipher.h"

using CryptoPP::AutoSeededRandomPool;
using CryptoPP::Integer;
using CryptoPP::ECDH;
using CryptoPP::DL_GroupParameters_EC;


//                                                                                  zero out the keys
ecdhe::ecdhe(bool isServer, HashFunction* hash) : AsymetricCipher(isServer, hash), _preMasterSecret((size_t)PRE_MASTER_SECRET_SIZE), _masterSecret((size_t)MASTER_SECRET_SIZE)
{
    _curve = CryptoPP::ASN1::secp256r1();  // Initialize Curve
    AutoSeededRandomPool rng;  // Initialize random

    _privateKeyInstance.Initialize(rng, _curve);  // generate private key
    _privateKeyInstance.MakePublicKey(_publicKeyInstance);  // generate public key

    //Extract private key to raw bytes
    const Integer& privateExponent = _privateKeyInstance.GetPrivateExponent();
    _privateKeyByteBlock = SecByteBlock(privateExponent.MinEncodedSize());
    privateExponent.Encode(_privateKeyByteBlock, _privateKeyByteBlock.size());

    //copy to our raw key variable
    memcpy(_privateKey.first(), (const void*)(_privateKeyByteBlock.data()), MAX_KEY_SIZE);


    //Extract public key to raw bytes
    const ECP::Point& publicPoint = _publicKeyInstance.GetPublicElement();
    _publicKeyByteBlock = SecByteBlock(_publicKeyInstance.GetGroupParameters().GetCurve().EncodedPointSize());
    _publicKeyInstance.GetGroupParameters().GetCurve().EncodePoint(
        _publicKeyByteBlock, publicPoint, false);
    //copy to our raw key variable

    memcpy(_publicKey.first(), (const void*)(_publicKeyByteBlock.data()), MAX_KEY_SIZE);


}


// function for returning master secret
bytes ecdhe::keyExchange(const bytes& otherPublicKey, const bytes& clientRandom, const bytes& serverRandom)
{
    ECDH<ECP>::Domain dhA(_curve);
    SecByteBlock sharedSecret(dhA.AgreedValueLength());

    //raw other key
    SecByteBlock rawKey((CryptoPP::byte*)otherPublicKey.data(), otherPublicKey.size());


    //get the curve to make the exchange
    ECP ec = DL_GroupParameters_EC<ECP>(_curve).GetCurve();

    // Decode the raw key into a point on the curve
    ECP::Point publicKeyPoint;
    ec.DecodePoint(publicKeyPoint, rawKey, rawKey.size());

    // Create the public key instance
    ECIES<ECP>::PublicKey publicKey;
    publicKey.Initialize(DL_GroupParameters_EC<ECP>(_curve), publicKeyPoint);



    //key exchange
    if (!dhA.Agree(sharedSecret, _privateKeyByteBlock, rawKey))
    {
        throw std::exception("(edche::keyExchange): While Calling ECDH<ECP>::Domain.Agree(), Key Exchange Failed!!");
    }

    //this->_preMasterSecret.resize(PRE_MASTER_SECRET_SIZE, '\0');//resize the pre master secret
    //no need for this line anymore, made the ctor initialize it at this size
    memcpy(_preMasterSecret.first(), sharedSecret.data(), PRE_MASTER_SECRET_SIZE);


    return this->calculateMasterSecret(clientRandom, serverRandom);
}


bytes ecdhe::calculateMasterSecret(const bytes& clientRandom, const bytes& serverRandom)//haven't checked this, should work no problem, need to check it, found a problem
{
    bytes rawPreMasterSecert(_preMasterSecret.first(), PRE_MASTER_SECRET_SIZE);//turn preMaster into bytes
    const bytes label("master secret");//generate the label

    bytes seed;//generate the seed
    seed.concat(clientRandom);
    seed.concat(serverRandom);

    //calculate the master secret
    this->_masterSecret = prf_sha<CryptoPP::SHA256>(_preMasterSecret, label, seed, MASTER_SECRET_SIZE);

    return this->_masterSecret;
}
