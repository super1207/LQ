#include "Reader.h"

uint8_t Reader::readUInt8(const void* buf)
{
    return ((const uint8_t*)buf)[0];
}

uint8_t Reader::readUInt8(const std::string& buf, size_t offset)
{
    if (buf.size() < offset + 1)
    {
        throw std::runtime_error("readUInt8 err");
    }
    return readUInt8(buf.data() + offset);
}

uint16_t Reader::readUInt16BE(const void* buf)
{
    //return ((uint16_t)(((uint8_t *)buf)[0]))*256 + ((uint8_t)((uint8_t *)buf)[1]);
    return be16toh(((const uint16_t*)buf)[0]);
}

uint16_t Reader::readUInt16BE(const std::string& buf, size_t offset)
{
    if (buf.size() < offset + 2)
    {
        throw std::runtime_error("readUInt16BE err");
    }
    return readUInt16BE(buf.data() + offset);
}

uint32_t Reader::readUInt32BE(const void* buf)
{
    return be32toh(((const uint32_t*)buf)[0]);
}

uint32_t Reader::readUInt32BE(const std::string& buf, size_t offset)
{
    if (buf.size() < offset + 4)
    {
        throw std::runtime_error("readUInt32BE err");
    }
    return readUInt32BE(buf.data() + offset);
}

uint64_t Reader::readUInt64BE(const std::string& buf, size_t offset)
{
    if (buf.size() < offset + 8)
    {
        throw std::runtime_error("readUInt64BE err");
    }
    return readUInt64BE(buf.data() + offset);
}
uint64_t Reader::readUInt64BE(const void* buf)
{
    return be64toh(((const uint64_t*)buf)[0]);
}

std::map<uint16_t, std::string> Reader::readTlv(const std::string& buf, size_t offset)
{
    std::map<uint16_t, std::string> t;
    while (buf.size() > 2 + offset)
    {
        const uint16_t k = readUInt16BE(buf, offset);
        offset += 2;
        const uint16_t readlen = readUInt16BE(buf, offset);
        offset += 2;
        t.insert({ k,buf.substr(offset,readlen) });
        offset = offset + readlen;
    }
    return t;
}
