#include "constants.hpp"


void PrintHex(const std::string& label, const CryptoPP::SecByteBlock& data)
{
    std::cout << label;
    CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(std::cout));
    encoder.Put(data, data.size());
    encoder.MessageEnd();
    std::cout << std::endl;
}
void PrintHexStr(const std::string& label, const bytes& data)
{
    CryptoPP::SecByteBlock a((unsigned char*)(&data[0]), data.size());

    std::cout << label;
    CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(std::cout));
    encoder.Put(a, a.size());
    encoder.MessageEnd();
    std::cout << std::endl;
}
void PrintHexStr(std::ostream& os, const std::string& label, const bytes& data)
{
	CryptoPP::SecByteBlock a((unsigned char*)(&data[0]), data.size());

	os << label;
	CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(os));
	encoder.Put(a, a.size());
	encoder.MessageEnd();
	os << std::endl;
}


Integer gf_mult(const Integer& x, const Integer& y) {
	const Integer IRREDUCIBLE_POLY("0xE1000000000000000000000000000000");
	Integer result("0x0");
	Integer x_copy = x;
	Integer y_copy = y;

	for (int i = 127; i >= 0; --i) {
		if (y_copy.GetBit(i)) {
			result ^= x_copy;
		}
		bool x_bit = x_copy.GetBit(0); 
		x_copy >>= 1;
		if (x_bit) {
			x_copy ^= IRREDUCIBLE_POLY;
		}
	}
	return result;
}

Integer h_mult(const Integer& h, Integer val) {
	Integer product("0x0");

	for (int i = 0; i < 16; ++i) {
		Integer byte_val = (val & 0xFF);

		product ^= gf_mult(h, byte_val << (8 * i));
		val >>= 8;
	}


	return product;
}

void nb_to_n_bytes(uint64_t value, size_t len, byte* out) {
	for (size_t i = 0; i < len; ++i) {
		out[len - i - 1] = (byte)(value >> (8 * i));
	}
}

Integer ghash(const Integer& h, const byte* a, size_t a_len, const byte* c, size_t c_len)
{	
	size_t aPaddedLen = (a_len + 15) / 16 * 16; 
	std::vector<byte> paddedA(aPaddedLen, 0); 
	memcpy(paddedA.data(), a, a_len); 

	Integer A_padded_int(paddedA.data(), aPaddedLen);

	size_t cPaddedLen = (c_len + 15) / 16 * 16;
	std::vector<byte> paddedC(cPaddedLen, 0);
	memcpy(paddedC.data(), c, c_len);
	Integer tag = h_mult(h, A_padded_int);
	for (size_t i = 0; i < cPaddedLen / 16; i++) {
		Integer c_block(paddedC.data() + i * 16, 16);
		tag ^= c_block;          
		tag = h_mult(h, tag);
	}
	byte len_combined[16] = { 0 };
	nb_to_n_bytes(8 * a_len, 8, len_combined); 
	nb_to_n_bytes(8 * c_len, 8, len_combined + 8);

	Integer len_combined_int(len_combined, 16);
	tag ^= len_combined_int; 
	tag = h_mult(h, tag); 


	return tag;
}

unsigned long long bytesToInt(bytes& data)
{
	const size_t size = data.size();
	unsigned long long dst = 0;
	int i = 0;
	for (i = 0; i < size; i++)
	{
		dst <<= BYTE_SIZE;
		dst += (byte)data[i];
	}

	return dst;
}

unsigned long long bytesToInt(bytes& data, size_t start, size_t end)
{
	bytes sliced = data.slice(start, end);

	return bytesToInt(sliced);
}
