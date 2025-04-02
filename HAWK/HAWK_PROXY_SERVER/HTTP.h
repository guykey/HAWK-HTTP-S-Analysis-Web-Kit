#pragma once


#include <iostream>
#include <unordered_map>
#include <string>
#include "../HAWK_TLS/constants.hpp"

#include <zlib.h>



class HTTPRequest
{
public:
	HTTPRequest(const bytes& request);

	inline const bytes& getRaw() const
	{
		return this->_raw;
	}

    void setRaw(const bytes& raw)
    {
        this->_raw = raw;
        parse();
    }

    bytes fullRequest();

    void changeContent(const bytes& newRequestRaw);

	const std::string& getMethod() const;
	const std::string& getHost() const;

	const std::string& getHeader(const std::string& header) const;

	friend std::ostream& operator<<(std::ostream& buff, const HTTPRequest& other);

	const std::string& getBody();



private:
	void parse();
	bytes _raw;
    bytes _rawHeaders;
    bytes _body;
	mutable std::unordered_map<std::string, std::string> _headers;
	std::string _host;

	std::string _httpVersion;
	std::string _method;
	std::string _request;
};



class ZlibCompression
{
public:
	static int compressData(const bytes& input, bytes& output);
	static int decompressData(const bytes& input, bytes& output);

    static bytes findGzipStart(const bytes& input) {
        for (size_t i = 0; i < input.size() - 1; ++i) {
            if (input[i] == 0x1F && input[i + 1] == 0x8B) {
                return input.slice(i, input.size());
            }
        }
        return input; // If no gzip header found, return original
    }

    // Function to decompress Gzip data using zlib
    static bool decompressGzip(const bytes& compressed, bytes& decompressed) {
        z_stream strm{};
        strm.next_in = (Bytef*)compressed.data();
        strm.avail_in = compressed.size();

        if (inflateInit2(&strm, 15 + 16) != Z_OK) {
            std::cerr << "inflateInit2 failed!" << std::endl;
            return false;
        }

        decompressed.resize(compressed.size() * 3); // Start with a large enough buffer

        int ret;
        do {
            strm.avail_out = decompressed.size() - strm.total_out;
            strm.next_out = (byte*)decompressed.data() + strm.total_out;

            ret = inflate(&strm, Z_NO_FLUSH);

            if (ret == Z_BUF_ERROR) {
                decompressed.resize(decompressed.size() * 2); // Resize buffer and continue
            }
            else if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
                std::cerr << "Decompression failed! Error: " << ret << std::endl;
                inflateEnd(&strm);
                return false;
            }
        } while (ret != Z_STREAM_END);

        decompressed.resize(strm.total_out); // Trim buffer to actual size
        inflateEnd(&strm);
        return true;
    }
};




