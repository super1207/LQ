#pragma once

#include <string>

class Writer
{
    public:
        Writer& writeU8(uint8_t num);
        Writer& writeU16(uint16_t num);
        Writer& write32(int32_t num);
        Writer& writeU32(uint32_t num);
        Writer& writeU64(uint64_t num);
        Writer& writeBytes(const std::string& s);
        Writer& writeWithLength(const std::string& s);
        Writer& writeTlv(const std::string& s);
        Writer& writeDouble(double s);
        std::string read();
    private:
        std::string dat;
};