#include "Writer.h"

#include <string>
#include <portable_endian/portable_endian.h>
#include <cstring>
#include <assert.h>

 Writer& Writer::writeU8(uint8_t num)
{
    dat.push_back(num);
    return *this;
}

 Writer& Writer::writeU16(uint16_t num)
{
    dat.resize(dat.size() + 2);
    (*((uint16_t*)(&dat[dat.size() - 2]))) = htobe16(num);
    return *this;
}

 Writer& Writer::write32(int32_t num)
{
    dat.resize(dat.size() + 4);
    (*((int32_t*)(&dat[dat.size() - 4]))) = htobe32(num);
    return *this;
}

 Writer& Writer::writeU32(uint32_t num)
{
    dat.resize(dat.size() + 4);
    (*((uint32_t*)(&dat[dat.size() - 4]))) = htobe32(num);
    return *this;
}

 Writer& Writer::writeU64(uint64_t num)
{
    dat.resize(dat.size() + 8);
    (*((uint64_t*)(&dat[dat.size() - 8]))) = htobe64(num);
    return *this;
}

 Writer& Writer::writeBytes(const std::string& s)
{
    dat.resize(dat.size() + s.size());
    memcpy(&dat[dat.size() - s.size()], s.data(), s.size());
    return *this;
}

 Writer& Writer::writeWithLength(const std::string& s)
{
    writeU32(s.size() + 4);
    writeBytes(s);
    return *this;
}

 Writer& Writer::writeTlv(const std::string& s)
{
    assert(s.size() <= UINT16_MAX);
    writeU16((uint16_t)s.size());
    writeBytes(s);
    return *this;
}

 Writer& Writer::writeDouble(double num)
 {
     uint64_t n = 0;
     memcpy_s((void*)n, 8, &num, 8);
     return writeU64(n);
 }

 std::string Writer::read()
{
    return dat;
}
