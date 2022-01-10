#include "QQClient.h"

#include "./tool/Writer.h"
#include "./tool/Common.h"
#include "./tool/QQTEA.h"
#include "./pb/data.pb.h"

using namespace std;

string QQClient::buildTlv(uint16_t tag)
{
    Writer w;
    w.writeU16(tag);
    std::string t;
    if (tag == 0x01)
    {
    t = Writer()
        .writeU16(1) // ip ver
        .writeBytes(Common::randomBytes(4))
        .writeU32(this->uin)
        .write32(Common::dateNow() & 0xffffffff)
        .writeBytes(string(4, '\0')) //ip
        .writeU16(0)
        .read();
    }
    else if (tag == 0x08)
    {
        t = Writer()
            .writeU16(0)
            .writeU32(2052)
            .writeU16(0)
            .read();
    }
    else if (tag == 0x16)
    {
        Apk apk = apklist.at((int)Apk::Platform::Watch);
        t = Writer()
            .writeU32(7)
            .writeU32(apk.appid)
            .writeU32(apk.subid)
            .writeBytes(device.guid)
            .writeTlv(apk.id)
            .writeTlv(apk.ver)
            .writeTlv(apk.sign)
            .read();
    }
    else if (tag == 0x18)
    {
        t = Writer()
            .writeU16(1) // ping ver
            .writeU32(1536)
            .writeU32(apk.appid)
            .writeU32(0) // app client ver
            .writeU32(uin)
            .writeU16(0)
            .writeU16(0)
            .read();
    }
    else if (tag == 0x1B)
    {
        t = Writer()
            .writeU32(0)
            .writeU32(0)
            .writeU32(3)
            .writeU32(4)
            .writeU32(72)
            .writeU32(2)
            .writeU32(2)
            .writeU16(0)
            .read();
    }
    else if (tag == 0x1D)
    {
        t = Writer()
            .writeU8(1)
            .writeU32(184024956)
            .writeU32(0)
            .writeU8(0)
            .writeU32(0)
            .read();
    }
    else if (tag == 0x1F)
    {
        t = Writer()
            .writeU8(0)
            .writeTlv("android")
            .writeTlv("7.1.2")
            .writeU16(2)
            .writeTlv("China Mobile GSM")
            .writeTlv("")
            .writeTlv("wifi")
            .read();
    }
    else if (tag == 0x33)
    {
        t = Writer()
            .writeBytes(device.guid)
            .read();
    }
    else if (tag == 0x35)
    {
        t = Writer()
            .writeU32(8)
            .read();
    }
    else if (tag == 0x100)
    {
        int emp = 0;
        t = Writer()
            .writeU16(1) // db buf ver
            .writeU32(7) // sso ver, dont over 7
            .writeU32(apk.appid)
            .writeU32(emp ? 2 : apk.subid)
            .writeU32(0) // app client ver
            .writeU32(apk.sigmap)
            .read();
    }
    else if (tag == 0x104)
    {
        t = Writer()
            .writeBytes(sig.t104)
            .read();
    }
    else if (tag == 0x107)
    {
        t = Writer()
            .writeU16(0)    // pic type
            .writeU8(0)     // captcha type
            .writeU16(0)    // pic size
            .writeU8(1)     // ret type
            .read();
    }
    else if (tag == 0x109)
    {
        t = Writer().writeBytes(Common::makeMd5(device.imei))
            .read();
    }
    else if (tag == 0x116)
    {
        t = Writer()
            .writeU8(0)
            .writeU32(apk.bitmap)
            .writeU32(0x10400) // sub sigmap
            .writeU8(1) // size of app id list
            .writeU32(1600000226) // app id list[0]
            .read();
    }
    else if (tag == 0x124)
    {
        t = Writer()
            .writeTlv(device.os_type.substr(0, 16))
            .writeTlv(device.version.release.substr(0, 16))
            .writeU16(2) // network type
            .writeTlv(device.sim.substr(0, 16))
            .writeU16(0)
            .writeTlv(device.apn.substr(0, 16))
            .read();
    }
    else if (tag == 0x128)
    {
        t = Writer()
            .writeU16(0)
            .writeU8(0) // guid new
            .writeU8(1) // guid available
            .writeU8(0) // guid changed
            .writeU32(16777216) // guid flag
            .writeTlv(device.model.substr(0, 32))
            .writeTlv(device.guid.substr(0, 16))
            .writeTlv(device.brand.substr(0, 16))
            .read();
    }
    else if (tag == 0x141)
    {
        t = Writer()
            .writeU16(1) // ver
            .writeTlv(device.sim)
            .writeU16(2) // network type
            .writeTlv(device.apn)
            .read();
    }
    else if (tag == 0x142)
    {
        t = Writer()
            .writeU16(0)
            .writeTlv(apk.id.substr(0, 32))
            .read();
    }
    else if (tag == 0x144)
    {
        const auto  body = Writer()
            .writeU16(5) // tlv cnt
            .writeBytes(buildTlv(0x109))
            .writeBytes(buildTlv(0x52d))
            .writeBytes(buildTlv(0x124))
            .writeBytes(buildTlv(0x128))
            .writeBytes(buildTlv(0x16e))
            .read();
        t = Writer().writeBytes(QQTEA::encode(sig.tgtgt, body)).read();

    }
    else if (tag == 0x145)
    {
        t = Writer()
            .writeBytes(device.guid)
            .read();
    }
    else if (tag == 0x147)
    {
        t = Writer()
            .writeU32(apk.appid)
            .writeTlv(apk.ver.substr(0, 5))
            .writeTlv(apk.sign)
            .read();
    }
    else if (tag == 0x154)
    {
        t = Writer()
            .writeU32(sig.seq + 1)
            .read();
    }
    else if (tag == 0x16e)
    {
        t = Writer().writeBytes(device.model)
            .read();
    }
    else if (tag == 0x177)
    {
        t = Writer()
            .writeU8(0x01)
            .writeU32(apk.buildtime)
            .writeTlv(apk.sdkver)
            .read();
    }
    else if (tag == 0x187)
    {
        t = Writer()
            .writeBytes(Common::makeMd5(device.mac_address))
            .read();
    }
    else if (tag == 0x188)
    {
        t = Writer()
            .writeBytes(Common::makeMd5(device.android_id))
            .read();
    }
    else if (tag == 0x191)
    {
        t = Writer().writeU8(0x82)
            .read();
    }
    else if (tag == 0x194)
    {
        t = Writer()
            .writeBytes(device.imsi)
            .read();
    }
    else if (tag == 0x202)
    {
        t = Writer()
            .writeTlv(device.wifi_bssid.substr(0, 16))
            .writeTlv(device.wifi_ssid.substr(0, 32))
            .read();
    }
    else if (tag == 0x401)
    {
        t = Writer()
            .writeBytes(Common::randomBytes(16))
            .read();
    }
    else if (tag == 0x511)
    {
        const vector<string> domains = {
        "aq.qq.com",
        "buluo.qq.com",
        "connect.qq.com",
        "docs.qq.com",
        "game.qq.com",
        "gamecenter.qq.com",
        // "graph.qq.com",
        "haoma.qq.com",
        "id.qq.com",
        // "imgcache.qq.com",
        "kg.qq.com",
        "mail.qq.com",
        "mma.qq.com",
        "office.qq.com",
        // "om.qq.com",
        "openmobile.qq.com",
        "qqweb.qq.com",
        "qun.qq.com",
        "qzone.qq.com",
        "ti.qq.com",
        "v.qq.com",
        "vip.qq.com",
        "y.qq.com",
        };
        auto stream = Writer().writeU16(domains.size());
        for (auto& v : domains)
        {
            stream.writeU8(0x01).writeTlv(v);
        }
        t = stream.read();
    }
    else if (tag == 0x516)
    {
        t = Writer().writeU32(0)
            .read();
    }
    else if (tag == 0x521)
    {
        t = Writer()
            .writeU32(0) // product type
            .writeU16(0) // const
            .read();
    }
    else if (tag == 0x52d)
    {
        const auto d = this->device;
        pb::DeviceInfo info;
        info.set_bootloader(d.bootloader);
        info.set_procversion(d.proc_version);
        info.set_codename(d.version.codename);
        info.set_incremental(to_string(d.version.incremental));
        info.set_fingerprint(d.fingerprint);
        info.set_bootid(d.boot_id);
        info.set_androidid(d.android_id);
        info.set_baseband(d.baseband);
        info.set_innerversion(to_string(d.version.incremental));
        string buf;
        info.SerializeToString(&buf);
        t = Writer().writeBytes(buf).read();
    }
    else
    {
        throw std::logic_error("unkow tlv tag:" + to_string(tag));
    }
    return w.writeTlv(t).read();
}