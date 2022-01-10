/* 参考： https://github.com/Mrs4s/MiraiGo/blob/master/binary/tea.go */
#include "./qqtea.h"
#include <string>
#include <stdexcept>
#include <cassert>
#include <cstring>
#include <portable_endian/portable_endian.h>
#include <random>

static std::string randomBytes(size_t n)
{
    using namespace std;
    string ret_buf(n, '\0');
    random_device rd;
    uniform_int_distribution<uint32_t> dist(0, UINT8_MAX);
    for (size_t i = 0; i < n; ++i)
        ret_buf[i] = dist(rd);
    return ret_buf;
}

/*
 * 描述:用qqtea来加密
 * 参数key:长度必须为16
 * 参数out_buf_len:加密后的数据长度
 * 返回值:加密后的数据，使用qqtea_free来释放
 */
static unsigned char *qqtea_encode(const unsigned char *key, const unsigned char *buffer, uint32_t len, uint32_t *out_buf_len)
{
    const uint32_t fill = (8 - (len + 2)) % 8 + 2;
    const uint32_t ret_buf_len = 1 + fill + len + 7;
    unsigned char *ret_buffer = (unsigned char *)malloc(ret_buf_len);
    if (!ret_buffer)
    {
        (*out_buf_len) = 0;
        return NULL;
    }
    ret_buffer[0] = ((uint8_t)(fill - 2)) | 0xF8;
    /* memset(ret_buffer+1,0xAD,fill); */
    auto rbuf = randomBytes(fill);
    memcpy(ret_buffer+1,rbuf.data(),fill);
    memset(ret_buffer+1,0,fill);
    memcpy(ret_buffer + fill + 1, buffer, len);
    memset(ret_buffer + 1 + fill + len, '\0', 7);
    uint32_t t0 = be32toh(*((uint32_t *)&key[0]));
    uint32_t t1 = be32toh(*((uint32_t *)&key[4]));
    uint32_t t2 = be32toh(*((uint32_t *)&key[8]));
    uint32_t t3 = be32toh(*((uint32_t *)&key[12]));
    uint64_t iv1 = 0, iv2 = 0, holder;
    for (uint32_t i = 0; i < ret_buf_len; i += 8)
    {
        uint64_t block = be64toh(*((uint64_t *)&ret_buffer[i]));
        holder = block ^ iv1;
        {
            uint32_t v0 = (uint32_t)(holder >> 32);
            uint32_t v1 = (uint32_t)(holder);
            v0 += (v1 + 0x9e3779b9) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0x9e3779b9) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0x3c6ef372) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0x3c6ef372) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0xdaa66d2b) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0xdaa66d2b) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0x78dde6e4) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0x78dde6e4) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0x1715609d) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0x1715609d) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0xb54cda56) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0xb54cda56) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0x5384540f) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0x5384540f) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0xf1bbcdc8) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0xf1bbcdc8) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0x8ff34781) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0x8ff34781) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0x2e2ac13a) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0x2e2ac13a) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0xcc623af3) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0xcc623af3) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0x6a99b4ac) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0x6a99b4ac) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0x08d12e65) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0x08d12e65) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0xa708a81e) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0xa708a81e) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0x454021d7) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0x454021d7) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0xe3779b90) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0xe3779b90) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            iv1 = ((uint64_t)(v0) << 32 | (uint64_t)(v1));
        }
        iv1 = iv1 ^ iv2;
        iv2 = holder;
        (*((uint64_t *)(&ret_buffer[i]))) = htobe64(iv1);
    }
    (*out_buf_len) = ret_buf_len;
    return ret_buffer;
}

/*
 * 描述:用qqtea来解密
 * 参数key:长度必须为16
 * 参数out_buf_len:解密后的数据长度
 * 返回值:解密后的数据，使用qqtea_free来释放
 */
static unsigned char *qqtea_decode(const unsigned char *key, const unsigned char *buffer, uint32_t len, uint32_t *out_buf_len)
{
    if (len < 16 || len % 8 != 0)
    {
        (*out_buf_len) = 0;
        return NULL;
    }
    unsigned char *ret_buffer = (unsigned char *)malloc(len);
    if (!ret_buffer)
    {
        (*out_buf_len) = 0;
        return NULL;
    }
    uint32_t t0 = be32toh(*((uint32_t *)&key[0]));
    uint32_t t1 = be32toh(*((uint32_t *)&key[4]));
    uint32_t t2 = be32toh(*((uint32_t *)&key[8]));
    uint32_t t3 = be32toh(*((uint32_t *)&key[12]));
    uint64_t iv1 = 0, iv2 = 0, holder = 0, tmp = 0;
    for (uint32_t i = 0; i < len; i += 8)
    {
        uint64_t block = be64toh(*((uint64_t *)&buffer[i]));
        {
            uint64_t n = block ^ iv2;
            uint32_t v0 = (uint32_t)(n >> 32);
            uint32_t v1 = (uint32_t)(n);
            v1 -= (v0 + 0xe3779b90) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0xe3779b90) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0x454021d7) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0x454021d7) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0xa708a81e) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0xa708a81e) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0x08d12e65) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0x08d12e65) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0x6a99b4ac) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0x6a99b4ac) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0xcc623af3) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0xcc623af3) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0x2e2ac13a) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0x2e2ac13a) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0x8ff34781) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0x8ff34781) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0xf1bbcdc8) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0xf1bbcdc8) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0x5384540f) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0x5384540f) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0xb54cda56) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0xb54cda56) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0x1715609d) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0x1715609d) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0x78dde6e4) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0x78dde6e4) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0xdaa66d2b) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0xdaa66d2b) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0x3c6ef372) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0x3c6ef372) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0x9e3779b9) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0x9e3779b9) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            tmp = ((uint64_t)(v0) << 32 | (uint64_t)(v1));
        }
        iv2 = tmp;
        holder = tmp ^ iv1;
        iv1 = block;
        (*((uint64_t *)(&ret_buffer[i]))) = htobe64(holder);
    }
    if(ret_buffer[len-1] != 0
    || ret_buffer[len-2] != 0
    || ret_buffer[len-3] != 0
    || ret_buffer[len-4] != 0
    || ret_buffer[len-5] != 0
    || ret_buffer[len-6] != 0
    || ret_buffer[len-7] != 0
    )
    {
        free(ret_buffer);
        (*out_buf_len) = 0;
        return NULL;
    }
    (*out_buf_len) = len - ((ret_buffer[0] & 7) + 3) - 7;
    unsigned char *ret_buffer2 = (unsigned char *)malloc(*out_buf_len);
    if (!ret_buffer2)
    {
        free(ret_buffer);
        (*out_buf_len) = 0;
        return NULL;
    }
    memcpy(ret_buffer2, ret_buffer + ((ret_buffer[0] & 7) + 3), (*out_buf_len));
    free(ret_buffer);
    return ret_buffer2;
}

/* 
 * 描述:释放加解密函数返回指针指向的内存(空指针安全)
 */
#define qqtea_free(buffer) free(buffer)
// static inline void qqtea_free(unsigned char *buffer)
// {
//     free(buffer);
// }

std::string QQTEA::encode(const std::string &key, const std::string &data)
{
    uint32_t out_len;
    assert(key.size() == 16);
    unsigned char *out_buf = qqtea_encode((const unsigned char *)key.data(), (const unsigned char *)data.data(), data.size(), &out_len);
    if (!out_buf)
    {
        throw std::runtime_error("qqtea_encode error");
    }
    std::string retstr((const char *)out_buf, out_len);
    qqtea_free(out_buf);
    return retstr;
}

std::string QQTEA::decode(const std::string &key, const std::string &data)
{
    uint32_t out_len;
    if (key.size() != 16)
    {
        throw std::runtime_error("the qqtea'key len not 16");
    }
    //assert(key.size() == 16);
    //printf("before decode key:");
    /*for(auto ch:key)
    {
        printf("%02X",(uint8_t)ch);
    }
    printf("\n");
    for(auto ch:data)
    {
        printf("%02X",(uint8_t)ch);
    }
    printf("\n");*/
    
    unsigned char *out_buf = qqtea_decode((const unsigned char *)key.data(), (const unsigned char *)data.data(), data.size(), &out_len);
    if (!out_buf)
    {
        throw std::runtime_error("qqtea_decode error");
    }
    std::string retstr((const char *)out_buf, out_len);
    qqtea_free(out_buf);
    //printf("after decode:\n");
    //for(auto ch:retstr)
    //{
    //    printf("%02X",(uint8_t)ch);
    //}
    //printf("\n");
    return retstr;
}
