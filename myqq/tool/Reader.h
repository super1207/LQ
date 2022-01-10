#pragma once

#include <string>
#include <portable_endian/portable_endian.h>
#include <cstring>
#include <stdexcept>
#include <map>

class Reader
{
public:
    static uint8_t readUInt8(const void* buf);
    static uint8_t readUInt8(const std::string& buf, size_t offset = 0);
    static uint16_t readUInt16BE(const void* buf);
    static uint16_t readUInt16BE(const std::string& buf, size_t offset = 0);
    static uint32_t readUInt32BE(const void* buf);
    static uint32_t readUInt32BE(const std::string& buf, size_t offset = 0);
    static uint64_t readUInt64BE(const std::string& buf, size_t offset = 0);
    static uint64_t readUInt64BE(const void* buf);
    static std::map<uint16_t, std::string> readTlv(const std::string& buf, size_t offset = 0);

};