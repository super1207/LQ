#include "qqecdh.h"

#include <ecdh/uECC.h>
#include <mmd5/mmd5.h>
#include <stdexcept>

QQECDH::QQECDH()
{
    std::string private_key;
    public_key.resize(64);
    private_key.resize(32);
    share_key.resize(32);
    const struct uECC_Curve_t *curves = uECC_secp256r1(); //= prime256v1
    if (!uECC_make_key((uint8_t *)public_key.data(), (uint8_t *)private_key.data(), curves))
    {
        throw std::runtime_error("uECC_make_key() failed");
    }
    public_key.insert(public_key.begin(),(char)0x04);
    if (!uECC_shared_secret((const uint8_t *)oicq_public_key.data() + 1, (const uint8_t *)private_key.data(), (uint8_t *)share_key.data(), curves))
    {
        throw std::runtime_error("uECC_shared_secret() failed");
    }
    share_key.resize(16);
    make_md5((uint8_t *)share_key.data(), 16, (uint8_t *)share_key.data());
}
std::string QQECDH::get_public_key() const
{
    return public_key;
}
std::string QQECDH::get_share_key() const
{
    return share_key;
}