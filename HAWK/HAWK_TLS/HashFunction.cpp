#include "HashFunction.h"

//i dont like this


HashFunction* sha1::_instance = nullptr;
HashFunction* sha224::_instance = nullptr;
HashFunction* sha256::_instance = nullptr;
HashFunction* sha384::_instance = nullptr;
HashFunction* sha512::_instance = nullptr;

//WHY WHY WHY WHY WHY


const bytes sha1::compute(const bytes& input)
{
    CryptoPP::SHA1 hash;
    bytes digest(_outputSize);

    // Compute hash
    CryptoPP::StringSource ss(input, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::ArraySink((CryptoPP::byte*)digest.data(), digest.size())
        )
    );

    return digest;
}

const bytes sha224::compute(const bytes& input)
{
    CryptoPP::SHA224 hash;
    bytes digest(_outputSize);

    // Compute hash
    CryptoPP::StringSource ss(input, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::ArraySink((CryptoPP::byte*)digest.data(), digest.size())
        )
    );

    return digest;
}

const bytes sha256::compute(const bytes& input)
{
    CryptoPP::SHA256 hash;
    bytes digest(_outputSize);

    // Compute hash
    CryptoPP::StringSource ss(input, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::ArraySink((CryptoPP::byte*)digest.data(), digest.size())
        )
    );

    return digest;
}

const bytes sha384::compute(const bytes& input)
{
    CryptoPP::SHA384 hash;
    bytes digest(_outputSize);

    // Compute hash
    CryptoPP::StringSource ss(input, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::ArraySink((CryptoPP::byte*)digest.data(), digest.size())
        )
    );

    return digest;
}

const bytes sha512::compute(const bytes& input)
{
    CryptoPP::SHA512 hash;
    bytes digest(_outputSize);

    // Compute hash
    CryptoPP::StringSource ss(input, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::ArraySink((CryptoPP::byte*)digest.data(), digest.size())
        )
    );

    return digest;
}
