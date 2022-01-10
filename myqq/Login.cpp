#include "QQClient.h"

#include "./tool/Writer.h"
#include "./tool/QQTEA.h"
#include "./tool/Common.h"
#include "pb/oidb/oidb0x769.pb.h"
#include "pb/oidb/oidb0x480.pb.h"
#include "./tool/JCE.h"

using namespace std;

void QQClient::login()
{
	// 获取二维码
	std::string buf = fetchQrcode();
	// 写入文件
	Common::writeBiniaryFile(buf.data(), buf.size(), "qrpic.png");
	// 等待扫码
	while (true)
	{
		auto ret = queryQrcodeResult();
		if (ret.retcode < 0)
		{
			printf("error:server is busy\n");
		}
		else if (!ret.retcode && ret.t106.size() && ret.tgtgt.size() && ret.t16a.size() && ret.t318.size())
		{
			printf("login success retcode:%d uin:%ld tgtgt size:%d \n",
				ret.retcode,
				ret.uin,
				ret.tgtgt.size()
			);
			this->uin = ret.uin;
			this->sig.tgtgt = ret.tgtgt;
			const auto body =
				Writer()
				.writeU16(9)
				.writeU16(24)
				.writeBytes(buildTlv(0x18))
				.writeBytes(buildTlv(0x1))
				.writeU16(0x106)
				.writeTlv(ret.t106)
				.writeBytes(buildTlv(0x116))
				.writeBytes(buildTlv(0x100))
				.writeBytes(buildTlv(0x107))
				.writeBytes(buildTlv(0x142))
				.writeBytes(buildTlv(0x144))
				.writeBytes(buildTlv(0x145))
				.writeBytes(buildTlv(0x147))
				.writeU16(0x16a)
				.writeTlv(ret.t16a)
				.writeBytes(buildTlv(0x154))
				.writeBytes(buildTlv(0x141))
				.writeBytes(buildTlv(0x8))
				.writeBytes(buildTlv(0x511))
				.writeBytes(buildTlv(0x187))
				.writeBytes(buildTlv(0x188))
				.writeBytes(buildTlv(0x194))
				.writeBytes(buildTlv(0x191))
				.writeBytes(buildTlv(0x202))
				.writeBytes(buildTlv(0x177))
				.writeBytes(buildTlv(0x516))
				.writeBytes(buildTlv(0x521))
				.writeU16(0x318)
				.writeTlv(ret.t318)
				.read();
			fnSendLogin("wtlogin.login", body);
			break;
		}
		hv_sleep(5);
	}
}

std::string QQClient::buildLoginPacket(const std::string& cmd, const std::string& body, int type)
{
	nextSeq();
	uint32_t uin = this->uin;
	uint32_t cmdid = 0x810;
	uint32_t subappid = this->apk.subid;

	if (cmd == "wtlogin.trans_emp")
	{
		uin = 0;
		cmdid = 0x812;
		subappid = apklist.at((int)Apk::Platform::Watch).subid;
	}
	std::string body1;
	if (type == 2)
	{
		body1 = Writer()
			.writeU8(0x02)
			.writeU8(0x01)
			.writeBytes(sig.randkey)
			.writeU16(0x131)
			.writeU16(0x01)
			.writeTlv(ecdh.get_public_key())
			.writeBytes(QQTEA::encode(ecdh.get_share_key(), body))
			.read();
		//printf("buildLoginPacket body size:%d\n",body1.size());
		body1 = Writer()
			.writeU8(0x02)
			.writeU16(29 + body1.size()) // 1 + 27 + body.length + 1
			.writeU16(8001)              // protocol ver
			.writeU16(cmdid)             // command id
			.writeU16(1)                 // const
			.writeU32(uin)
			.writeU8(3)    // const
			.writeU8(0x87) // encrypt type 7:0 69:emp 0x87:4
			.writeU8(0)    // const
			.writeU32(2)   // const
			.writeU32(0)   // app client ver
			.writeU32(0)   // const
			.writeBytes(body1)
			.writeU8(0x03)
			.read();
		//printf("buildLoginPacket body size:%d\n",body1.size());
	}
	else
	{
		body1 = body;
	}

	//printbuf(body1);
	//printf("sig.seq:%ld\n",sig.seq);
	auto sso = Writer()
		.writeWithLength(Writer()
			.writeU32(sig.seq)
			.writeU32(subappid)
			.writeU32(subappid)
			.writeBytes({ 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00 })
			.writeWithLength(sig.tgt)
			.writeWithLength(cmd)
			.writeWithLength(sig.session)
			.writeWithLength(device.imei)
			.writeU32(4)
			.writeU16(2)
			.writeU32(4)
			.read())
		.writeWithLength(body1)
		.read();
	//printf("buildLoginPacket body size:%d\n",sso.size());
	if (type == 1)
	{
		sso = QQTEA::encode(sig.d2key, sso);
	}
	else if (type == 2)
	{
		sso = QQTEA::encode(std::string(16, '\0'), sso);
	}
	return Writer()
		.writeWithLength(Writer()
			.writeU32(0x0A)
			.writeU8(type)
			.writeWithLength(sig.d2)
			.writeU8(0)
			.writeWithLength(to_string(uin))
			.writeBytes(sso)
			.read())
		.read();
}

std::string QQClient::buildCode2dPacket(uint16_t cmdid, uint32_t head, const std::string& body)
{
	return buildLoginPacket(
		"wtlogin.trans_emp",
		Writer()
		.writeU32(head)
		.writeU32(0x1000)
		.writeU16(0)
		.writeU32(0x72000000)
		.writeU32(time(NULL))
		.writeU8(2)
		.writeU16(44 + body.size())
		.writeU16(cmdid)
		.writeBytes(string(21, '\0'))
		.writeU8(3)
		.writeU16(0)
		.writeU16(50)
		.writeU32(sig.seq + 1)
		.writeU64(0)
		.writeBytes(body)
		.writeU8(3)
		.read());
}

void QQClient::fnSendLogin(const std::string& cmd, const std::string& body)
{
	const auto seq = getNextSeq();
	const auto pkt = buildLoginPacket(cmd, body);
	const auto pktret = sendAndWait(pkt, seq);
	decodeLoginResponse(pktret);
}


void QQClient::registerClient(bool logout)
{
	oidb::D769RspBody pb_struct;
	oidb::D769ConfigSeq * fg = pb_struct.add_configlist();
	fg->set_type(46);
	fg->set_version(time(NULL));
	fg = pb_struct.add_configlist();
	fg->set_type(283);
	fg->set_version(0);
	string pb_buf;
	pb_struct.SerializeToString(&pb_buf);

	std::string SvcReqRegister = JCE::encodeStruct(JCE::JCEStruct({
			JCE::JCEStruct((int64_t)(this->uin)),
			JCE::JCEStruct((int64_t)(logout ? 0 : 7)),
			JCE::JCEStruct((int64_t)0),
			JCE::JCEStruct(""),
			JCE::JCEStruct((int64_t)(logout ? 21 : 11)),
			JCE::JCEStruct((int64_t)0),
			JCE::JCEStruct((int64_t)0),
			JCE::JCEStruct((int64_t)0),
			JCE::JCEStruct((int64_t)0),
			JCE::JCEStruct((int64_t)0),
			JCE::JCEStruct((int64_t)(logout ? 44 : 0)),
			JCE::JCEStruct(this->device.version.sdk),
			JCE::JCEStruct((int64_t)1),
			JCE::JCEStruct(""),
			JCE::JCEStruct((int64_t)0),
			JCE::JCEStruct(),
			JCE::JCEStruct(this->device.guid,true),
			JCE::JCEStruct((int64_t)2052),
			JCE::JCEStruct((int64_t)0),
			JCE::JCEStruct(this->device.model),
			JCE::JCEStruct(this->device.model),
			JCE::JCEStruct(this->device.version.release),
			JCE::JCEStruct((int64_t)1),
			JCE::JCEStruct((int64_t)0),
			JCE::JCEStruct((int64_t)0),
			JCE::JCEStruct(),
			JCE::JCEStruct((int64_t)0),
			JCE::JCEStruct((int64_t)0),
			JCE::JCEStruct(""),
			JCE::JCEStruct((int64_t)0),
			JCE::JCEStruct(this->device.brand),
			JCE::JCEStruct(this->device.brand),
			JCE::JCEStruct(""),
			JCE::JCEStruct(pb_buf,true),
			JCE::JCEStruct((int64_t)0),
			JCE::JCEStruct(),
			JCE::JCEStruct((int64_t)0),
			JCE::JCEStruct(),
			JCE::JCEStruct((int64_t)1000),
			JCE::JCEStruct((int64_t)98)
		}));
	JCE::JCEStruct tmap;
	tmap.type = JCE::JCEStruct::TYPE::STR_MAP;
	tmap.str_map["SvcReqRegister"] = JCE::JCEStruct(SvcReqRegister,true);
	std::string body = JCE::encodeWrapper(tmap, "PushService", "SvcReqRegister");
	std::string pkg = buildLoginPacket("StatSvc.register", body, 1);
	std::string payload = sendAndWait(pkg, sig.seq);
	JCE::JCEStruct rsp = JCE::decodeWrapper(payload);
	bool result = rsp.int_map.at(9).int_data ? true : false;
	if (!result)
	{
		throw std::runtime_error("registerClient failed");
	}
	printf("login success!\n");
	while (true)
	{
		hv_sleep(30);
		this->heartbeat();
	}
	//loop->setInterval(10, std::bind(this->onTimer, std::placeholders::_1, this));
	//loop->run();
}

void QQClient::heartbeat()
{
	if (this->sig.hb480 == "")
	{
		std::string hb480 = Writer().write32(this->uin).read();
		hb480.push_back('\0');
		hb480.append(Writer().write32(0x19e39).read());
		oidb::hb480 hb;
		hb.set_m1(1152);
		hb.set_m2(9);
		hb.set_m4(hb480);
		string pb_buf;
		hb.SerializeToString(&pb_buf);
		this->sig.hb480 = pb_buf;
	}
	this->sendUni("OidbSvc.0x480_9_IMCore", this->sig.hb480);
	printf("runInLoop tid=%ld\n", hv_gettid());
}

void QQClient::onTimer(hv::TimerID timerID, QQClient* cli) {
	printf("tid=%ld timerID=%lu time=%lus\n", hv_gettid(), (unsigned long)timerID, (unsigned long)time(NULL));
	cli->heartbeat();
}

void QQClient::decodeLoginResponse(const std::string& payload1)
{
	const auto payload = QQTEA::decode(ecdh.get_share_key(), payload1.substr(16, payload1.size() - 1 - 16));
	size_t offset = 0;
	offset += 2;
	const uint8_t type = Reader::readUInt8(payload, offset);
	offset += 1;
	offset += 2;
	const auto t = Reader::readTlv(payload, offset);
	printf("decodeLoginResponse type:%d\n", type);
	if (type == 204)
	{
		sig.t104 = t.at(0x104);
		const auto body = Writer()
			.writeU16(20)
			.writeU16(4)
			.writeBytes(buildTlv(0x8))
			.writeBytes(buildTlv(0x104))
			.writeBytes(buildTlv(0x116))
			.writeBytes(buildTlv(0x401))
			.read();
		fnSendLogin("wtlogin.login", body);
	}
	if (type == 0)
	{
		try
		{
			T119Struct ret = decodeT119(t.at(0x119));
			sig.t104 = "";
			sig.t174 = "";
			printf("nickname:%s,gender:%d,age:%d\n", ret.nickname.c_str(), ret.gender, ret.age);
			registerClient();
		}
		catch (const std::exception & e)
		{
			printf("error %s\n", e.what());
			hv_sleep(1000);
			const auto body = Writer()
				.writeU16(20)
				.writeU16(4)
				.writeBytes(buildTlv(0x8))
				.writeBytes(buildTlv(0x104))
				.writeBytes(buildTlv(0x116))
				.writeBytes(buildTlv(0x401))
				.read();
			fnSendLogin("wtlogin.login", body);
		}


	}
}

T119Struct QQClient::decodeT119(const std::string& t119_)
{
	const auto t119 = QQTEA::decode(sig.tgtgt, t119_);
	size_t offset = 0;
	offset += 2;
	const auto t = Reader::readTlv(t119, offset);
	sig.tgt = t.at(0x10a);
	sig.skey = t.at(0x120);
	sig.d2 = t.at(0x143);
	sig.d2key = t.at(0x305);
	sig.tgtgt = Common::makeMd5(sig.d2key);
	sig.emp_time = time(NULL);
	if (t.find(0x512) != t.end())
	{
		const auto t512 = t.at(0x512);
		size_t offset = 0;
		uint16_t len = Reader::readUInt16BE(t512, offset);
		offset += 2;
		while (len-- > 0)
		{
			const auto domainlen = Reader::readUInt16BE(t512, offset);
			offset += 2;
			const auto domain = t512.substr(offset, domainlen);
			offset += domainlen;
			const auto pskeylen = Reader::readUInt16BE(t512, offset);
			offset += 2;
			const auto pskey = t512.substr(offset, pskeylen);
			offset += pskeylen;
			const auto pt4tokenlen = Reader::readUInt16BE(t512, offset);
			offset += 2;
			const auto pt4token = t512.substr(offset, pt4tokenlen);
			offset += pt4tokenlen;
			this->pskey[domain] = pskey;
		}
	}
	std::string token;
	token.append(sig.d2key);
	token.append(sig.d2);
	token.append(sig.tgt);
	const int age = Reader::readUInt8(t.at(0x11a).substr(2, 1));
	const int gender = Reader::readUInt8(t.at(0x11a).substr(3, 1));
	const auto nickname = t.at(0x11a).substr(5);
	return T119Struct{ token,nickname,gender,age };

}