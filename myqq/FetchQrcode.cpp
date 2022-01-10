#include "QQClient.h"

#include "./tool/Writer.h"
#include "./tool/QQTEA.h"

using namespace std;
 
string QQClient::fetchQrcode()
{
    uint32_t seq = getNextSeq();
    string payload =
        sendAndWait(
            buildCode2dPacket(
                0x31,
                0x11100,
                Writer()
                .writeU16(0)
                .writeU32(16)
                .writeU64(0)
                .writeU8(8)
                .writeTlv("")
                .writeU16(6)
                .writeBytes(buildTlv(0x16))
                .writeBytes(buildTlv(0x1B))
                .writeBytes(buildTlv(0x1D))
                .writeBytes(buildTlv(0x1F))
                .writeBytes(buildTlv(0x33))
                .writeBytes(buildTlv(0x35))
                .read()),
            seq);
    payload = QQTEA::decode(ecdh.get_share_key(), payload.substr(16, payload.size() - 16 - 1));
    size_t offset = 0;
    offset += 54;
    const uint32_t retcode = Reader::readUInt8(payload, offset);
    offset += 1;
    const uint16_t qrsiglen = Reader::readUInt16BE(payload, offset);
    offset += 2;
    const string qrsig = payload.substr(offset, qrsiglen);
    offset += qrsiglen;
    offset += 2;
    const auto tlv = Reader::readTlv(payload, offset);
    if (!retcode && (tlv.find(0x17) != tlv.end()))
    {
        sig.qrsig = qrsig;
    }
    else
    {
        throw runtime_error("获取二维码失败，请重试");
    }
    return tlv.at(0x17);
}

QueryQrcodeResultStruct QQClient::queryQrcodeResult()
{
    int retcode = -1;
    uint32_t uin = 0;
    string t106, t16a, t318, tgtgt;
    if (sig.qrsig.size() == 0)
    {
        return { retcode, uin, t106, t16a, t318, tgtgt };
    }
    try
    {
        uint32_t seq = getNextSeq();
        string payload = sendAndWait(
            buildCode2dPacket(
                0x12,
                0x6200,
                Writer()
                .writeU16(5)
                .writeU8(1)
                .writeU32(8)
                .writeU32(16)
                .writeTlv(sig.qrsig)
                .writeU64(0)
                .writeU8(8)
                .writeTlv("")
                .writeU16(0)
                .read()),
            seq);
        payload = QQTEA::decode(ecdh.get_share_key(), payload.substr(16, payload.size() - 16 - 1));
        size_t offset = 0;
        offset += 48;
        int len = Reader::readUInt16BE(payload, offset);
        offset += 2;
        if (len > 0)
        {
            len--;
            const int fg = (int)payload.at(0);
            offset += 1;
            if (fg == 2)
            {
                offset += 8;
                len -= 8;
            }
            if (len > 0)
                offset += len;
        }
        offset += 4;
        retcode = (int)payload.at(0);
        offset += 1;
        if (retcode == 0)
        {
            offset += 4;
            uin = Reader::readUInt32BE(payload, offset);
            offset += 4;
            offset += 6;
            const auto t = Reader::readTlv(payload, offset);
            t106 = t.at(0x18);
            t16a = t.at(0x19);
            t318 = t.at(0x65);
            tgtgt = t.at(0x1e);
        }
    }
    catch (const std::exception&)
    {
        //不能解析出来说明还没有扫码成功，阴间的二维码查询.
        //printf("error:%s\n",e.what());
    }

    return { retcode, uin, t106, t16a, t318, tgtgt };
}