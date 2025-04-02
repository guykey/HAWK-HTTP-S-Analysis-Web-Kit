#include "HTTP.h"
#include <sstream>
HTTPRequest::HTTPRequest(const bytes& request) : _raw(request)
{
	parse();
}



bytes HTTPRequest::fullRequest()
{
    bytes fullRequest = this->_rawHeaders + this->getBody();

    return fullRequest;
}

//you need to figure out how to do that
void HTTPRequest::changeContent(const bytes& newRequestRaw)
{
    //jonathan do
}

const std::string& HTTPRequest::getMethod() const
{
    return this->_method;
}

const std::string& HTTPRequest::getHost() const
{
    return this->_host;
}

const std::string& HTTPRequest::getHeader(const std::string& header) const
{
    if (this->_headers.find(header) != this->_headers.end())
        return this->_headers[header];
    return "";
}

const std::string& HTTPRequest::getBody()
{
    //calculate for gzip decoding
    if (this->getHeader("Content-Encoding") == "gzip")
    {
        bytes output;
        bytes compressedPart;
        
        volatile size_t startGzip = this->_body.find_first_of("\r\n\x1F\x8B");
        startGzip = (startGzip == std::string::npos) ? 0 : startGzip + 2;

        compressedPart = this->_body.substr(startGzip);
        if (ZlibCompression::decompressGzip(compressedPart, output))
            return output;
        return this->_body;
    }


    return this->_body;
}

void HTTPRequest::parse()
{
    std::istringstream stream(this->_raw);

    std::string line;

    // Parse request line
    std::getline(stream, line);
    std::istringstream request_line_stream(line);
    request_line_stream >> this->_method >> this->_request >> this->_httpVersion;

    // Parse headers
    while (std::getline(stream, line) && line != "\r") {
        size_t pos = line.find(": ");
        if (pos != std::string::npos) {
            std::string key = line.substr(0, pos);
            std::string value = line.substr(pos + 2, line.length() - pos - 3); // Remove \r
            this->_headers[key] = value;
        }
    }
    size_t headersSize = stream.tellg();

    this->_rawHeaders = this->_raw.slice(0, headersSize);

    // Parse body
    std::ostringstream body_stream;
    body_stream << stream.rdbuf();
    this->_body = body_stream.str();

    
    //parse host, sometimes, headers doesn't have host, so we use
    //the url requested, and trim it to be just the host
    if (this->_headers.find("Host") == this->_headers.end())
    {
        this->_host = this->_request;
        if (this->_host.find(":"))//port, usualy happends
        {
            this->_host = this->_host.substr(0, this->_host.find_last_of(":"));
        }
    }
    else
    {
        this->_host = this->_headers["Host"];
        if (this->_host.find(":"))//port, usualy happends
        {
            this->_host = this->_host.substr(0, this->_host.find_last_of(":"));
        }
    }

}

std::ostream& operator<<(std::ostream& buff, const HTTPRequest& other)
{
    buff << other._raw << std::endl;
    return buff;
}

int ZlibCompression::compressData(const bytes& input, bytes& output)
{
    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    // Initialize deflate stream
    int ret = deflateInit2(&strm, Z_BEST_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK) {
        std::cerr << "deflateInit failed: " << ret << std::endl;
        return ret;
    }

    strm.avail_in = input.size();
    strm.next_in = const_cast<Bytef*>((byte*)(input.data()));

    output.resize(input.size() * 2); // allocate buffer for compressed data
    strm.avail_out = output.size();
    strm.next_out = const_cast<Bytef*>((byte*)(output.data()));

    ret = deflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END) {
        std::cerr << "deflate failed: " << ret << std::endl;
        deflateEnd(&strm);
        return ret;
    }

    output.resize(strm.total_out);  // resize output to actual compressed size

    deflateEnd(&strm);
    return Z_OK;
}

int ZlibCompression::decompressData(const bytes& input, bytes& output)
{
    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    // Initialize inflate stream
    int ret = inflateInit2(&strm, 15 + 32);  // 32 allows for both zlib and gzip formats
    if (ret != Z_OK) {
        std::cerr << "inflateInit failed: " << ret << std::endl;
        return ret;
    }

    strm.avail_in = input.size();
    strm.next_in = const_cast<Bytef*>((byte*)(input.data()));

    output.resize(input.size() * 2);  // allocate buffer for decompressed data
    strm.avail_out = output.size();
    strm.next_out = const_cast<Bytef*>((byte*)(output.data()));

    ret = inflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END) {
        std::cerr << "inflate failed: " << ret << std::endl;
        inflateEnd(&strm);
        return ret;
    }

    output.resize(strm.total_out);  // resize output to actual decompressed size

    inflateEnd(&strm);
    return Z_OK;
}
