#include "QQClient.h"

using namespace std;

QQClient::QQClient()
{
	Apk watchApk;
	watchApk.id = "com.tencent.qqlite";
	watchApk.appid = 16;
	watchApk.sign = { (int8_t)0xa6, (int8_t)0xb7, (int8_t)0x45, (int8_t)0xbf, (int8_t)0x24, (int8_t)0xa2, (int8_t)0xc2, (int8_t)0x77, (int8_t)0x52, (int8_t)0x77, (int8_t)0x16, (int8_t)0xf6, (int8_t)0xf3, (int8_t)0x6e, (int8_t)0xb6, (int8_t)0x8d };
	watchApk.subid = 537064446;
	watchApk.ver = "2.0.5";
	watchApk.sigmap = 34869472;
	watchApk.sdkver = "6.0.0.236";
	watchApk.buildtime = 1559564731;
	watchApk.bitmap = 16252796;
	apklist = { watchApk, watchApk, watchApk, watchApk, watchApk, watchApk };
	Apk mbApk;
	mbApk.id = "com.tencent.mobileqq";
	mbApk.appid = 16;
	mbApk.sign = { (char)166, (char)183, (char)69, (char)191, (char)36, (char)162, (char)194, (char)119, (char)82, (char)119, (char)22, (char)246, (char)243, (char)110, (char)182, (char)141 };
	mbApk.subid = 537064989;
	mbApk.ver = "8.4.1";
	mbApk.sigmap = 34869472;
	mbApk.sdkver = "6.0.0.2428";
	mbApk.buildtime = 1591690260;
	mbApk.bitmap = 184024956;//16252796;
	this->apk = mbApk;
	/*loop = std::make_shared<hv::EventLoop>();
	loop->setInterval(30, std::bind(this->onTimer, std::placeholders::_1, this));
	loop->run();
	printf("loop run ok\n");*/
}

int main()
{
	printf("main runInLoop tid=%ld\n", hv_gettid());
	QQClient client;
	client.connect();
	client.login();
	while (1);
	return 0;
}

