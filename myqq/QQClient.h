#pragma once



#include <string>
#include <map>
#include <shared_mutex>
#include <vector>

#include <hv/TcpClient.h>
#include <hv/EventLoop.h>

#include "./tool/Common.h"
#include "./tool/Reader.h"
#include "./tool/QQECDH.h"

struct Device
{
    struct Version
    {
        std::string codename = "REL";
        uint32_t incremental = 4126100604;
        std::string release = "10";
        int64_t sdk = 29;
    };
    std::string mac_address = "00:50:AD:9F:56:AA";
    std::string imei = "864342052728871";
    std::string guid = Common::makeMd5(imei + mac_address);
    std::string imsi = Common::randomBytes(16);
    std::string android_id = "OICQX.637960.652";
    std::string sim = "T-Mobile";
    std::string apn = "wifi";
    std::string wifi_bssid = mac_address;
    std::string wifi_ssid = "TP-LINK-a9a0ea6f";
    std::string bootloader = "U-boot";
    std::string proc_version = "Linux version 4.19.71-20010 (konata@takayama.github.com)";
    std::string baseband;
    std::string boot_id = "18eb3c41-4e2a-ad9f-56aa-bc1af5ef4c7c";
    std::string fingerprint = "OICQX/MRS4S/HIM188MOE:10/OICQX.2451282.2161/4071737381:user/release-keys";
    Device::Version version;
    std::string os_type = "android";
    std::string model = "Konata 2020";
    std::string brand = "OICQX";
};

struct Sig
{
    uint32_t seq = Reader::readUInt32BE(Common::randomBytes(4)) & 0xfff;
    std::string randkey = Common::randomBytes(16);
    std::string tgt;
    std::string tgtgt = Common::randomBytes(16);
    std::string session = Common::randomBytes(4);
    std::string d2key;
    std::string d2;
    std::string qrsig;
    std::string t104;
    std::string t174;
    std::string skey;
    std::string hb480;
    uint32_t emp_time = 0;
};

struct Apk
{
    enum class Platform
    {
        Android = 1,
        aPad = 2,
        Watch = 3,
        iMac = 4,
        iPad = 5
    };
    uint32_t appid;
    uint32_t subid;
    std::string id;
    std::string ver;
    std::string sign;
    uint32_t sigmap;
    std::string sdkver;
    uint32_t buildtime;
    uint32_t bitmap;
};

struct QueryQrcodeResultStruct
{
    int retcode;
    uint32_t uin;
    std::string t106;
    std::string t16a;
    std::string t318;
    std::string tgtgt;
};

struct T119Struct
{
    std::string token;
    std::string nickname;
    int gender = 0;
    int age = 0;
};

class QQClient
{
public:
    QQClient();
	void connect();
    void login();
private:
	void doPackge(std::string& pkg);
    uint32_t getNextSeq();
    void nextSeq();
    void heartbeat();
    static void onTimer(hv::TimerID timerID, QQClient* cli);
    std::string buildCode2dPacket(uint16_t cmdid, uint32_t head, const std::string& body);
    std::string sendAndWait(const std::string& buf, uint32_t seq);
    std::string buildLoginPacket(const std::string& cmd, const std::string& body, int type = 2);
    std::string fetchQrcode();
    void fnSendLogin(const std::string& cmd, const std::string& body);
    void decodeLoginResponse(const std::string& payload1);
    QueryQrcodeResultStruct queryQrcodeResult();
    T119Struct decodeT119(const std::string& t119_);
    std::string buildTlv(uint16_t tag);
    void registerClient(bool logout = false);
    std::string sendUni(const std::string& cmd, const std::string body);
    hv::EventLoopPtr loop;
    std::vector<Apk> apklist;
    Apk apk;
    Device device;
    QQECDH ecdh;
    std::map<std::string, std::string> pskey;
	//状态信息
	Sig sig;
	uint32_t uin = 0;
	hv::TcpClient cli;
	//用于缓存数据包
	std::string pkgbuf;
	//保存从qq服务器收到的数据包
	std::shared_mutex mx_pkgmap;
	std::map<uint32_t, std::shared_ptr<std::string>> pkgmap;
};