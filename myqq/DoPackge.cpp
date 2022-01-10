#include "QQClient.h"

#include <string>
#include <memory.h>

#include "./tool/Reader.h"
#include "./tool/QQTEA.h"
#include "./tool/Common.h"
#include "./tool/Writer.h"

using namespace std;

void QQClient::doPackge(std::string& pkg)
{
    const uint8_t flag = Reader::readUInt8(pkg, 4);
    const std::string encrypted = pkg.substr(Reader::readUInt32BE(pkg, 6) + 6);
    std::string decrypted;
    printf("doPackge flag:%d\n", flag);
    switch (flag)
    {
    case 0:
        decrypted = encrypted;
        break;
    case 1:
        decrypted = QQTEA::decode(sig.d2key, encrypted);
        break;
    case 2:
        decrypted = QQTEA::decode(std::string(16, '\0'), encrypted);
        break;
    default:
        throw std::runtime_error("unknown flag:" + std::to_string(flag));
    }
    struct SsoStruct
    {
        uint32_t seq;
        std::string cmd;
        std::string payload;
        SsoStruct(const std::string& buf)
        {
            uint32_t headlen = Reader::readUInt32BE(buf);
            seq = Reader::readUInt32BE(buf, 4);
            const uint32_t retcode = Reader::readUInt32BE(buf, 8);
            if (retcode != 0)
            {
                throw std::runtime_error("In DoPackge.cpp:doPackge:unsuccessful retcode: " + std::to_string(retcode));
            }
            uint32_t offset = Reader::readUInt32BE(buf, 12) + 12;
            uint32_t len = Reader::readUInt32BE(buf, offset);
            if(len < 4)
                throw std::runtime_error("In DoPackge.cpp:doPackge:len < 4");
            cmd = buf.substr(offset + 4, len - 4);
            offset += len;
            len = Reader::readUInt32BE(buf, offset);
            offset += len;
            const uint32_t flag = Reader::readUInt32BE(buf, offset);
            if (flag == 0)
                payload = buf.substr(headlen + 4);
             else if (flag == 1)
                throw std::runtime_error("In DoPackge.cpp:doPackge:flag == 1");
                 //payload = unzip(buf.substr(headlen + 4)); //TODO
            else if (flag == 8)
                payload = buf.substr(headlen);
            else
                throw std::runtime_error("unknown compressed flag: " + std::to_string(flag));
        }
    };
    SsoStruct sso(decrypted);
    printf("sso cmd:%s,seq:%d size:%d\n", sso.cmd.c_str(), sso.seq, sso.payload.size());
    {
        shared_lock<shared_mutex> lock(mx_pkgmap);
        auto it = pkgmap.find(sso.seq);
        if (it == pkgmap.end())
        {
            return; //说明调用者已经没有监听了
        }
        it->second = shared_ptr<string>(new string(move(sso.payload)));
    }
}

uint32_t QQClient::getNextSeq()
{
    if (sig.seq + 1 >= 0x8000)
    {
        return 1;
    }
    return sig.seq + 1;
}

void QQClient::nextSeq()
{
    sig.seq = getNextSeq();
}


std::string QQClient::sendAndWait(const std::string& buf, uint32_t seq)
{
    {
        unique_lock<shared_mutex> lock(mx_pkgmap);
        pkgmap.insert({ seq, nullptr });
    }
    if (cli.send(buf.data(), buf.size()) != buf.size())
    {
        unique_lock<shared_mutex> lock(mx_pkgmap);
        pkgmap.erase(seq);
        throw std::runtime_error("send buf error");
    }
    std::string ret_buf;
    const bool is_ret =
        Common::waitUntil(5000,
            [&]() -> bool
            {
                shared_lock<shared_mutex> lock(mx_pkgmap);
                const auto find_ret = pkgmap.find(seq);
                if (find_ret->second != nullptr)
                {
                    ret_buf.assign(move(*(find_ret->second)));
                    return true;
                }
                return false;
            });
    unique_lock<shared_mutex> lock(mx_pkgmap);
    pkgmap.erase(seq);
    if (is_ret)
        return ret_buf;
    throw std::runtime_error("wait seq timeout");
}

std::string QQClient::sendUni(const std::string& cmd, const std::string body)
{
    this->nextSeq();
    uint32_t len = cmd.size() + 20;
    auto w = Writer().writeU32(len).writeU32(cmd.size() + 4).writeBytes(cmd);
    uint32_t offset = cmd.size() + 8;
    w.writeU32(8);
    w.writeBytes(sig.session);
    w.writeU32(4);
    w.write32(body.size() + 4);
    w.writeBytes(body);
    std::string sso = w.read();
    std::string encrypted = QQTEA::encode(sig.d2key, sso);
    std::string uin_str = std::to_string(this->uin);
    len = encrypted.size() + uin_str.size() + 18;
    std::string pkt = Writer().writeU32(len).writeU32(0x0B).writeU8(1)
        .write32(sig.seq)
        .writeU8(0)
        .writeU32(uin_str.size() + 4)
        .writeBytes(uin_str)
        .writeBytes(encrypted)
        .read();
    printf("sendUni seq:%d\n", sig.seq);
    std::string ret = sendAndWait(pkt, sig.seq);
    return ret;
}