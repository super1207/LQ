#include "QQClient.h"

#include "./tool/Reader.h"
#include "./tool/Common.h"

using namespace std;


void QQClient::connect()
{
	// 连接qq服务器
	if (cli.createsocket(8080, "msfwifi.3g.qq.com") < 0)
	{
		throw runtime_error("connect to msfwifi.3g.qq.com:8080 failed");
	}
	// 处理消息
	cli.onMessage = [this](const hv::SocketChannelPtr& channel, hv::Buffer* buf)
	{
		printf("runInLoop tid=%ld\n", hv_gettid());
		printf("cur buf len %ld,recive buf size:%ld\n", pkgbuf.size(), buf->len);
		if (pkgbuf.size() == 0)
			Common::assign(pkgbuf, buf->data(), buf->len);
		else
			Common::append(pkgbuf, buf->data(), buf->len);
		printf("cur buf len %ld\n", pkgbuf.size());
		while (pkgbuf.size() > 4)
		{
			uint32_t len = Reader::readUInt32BE(pkgbuf);
			if (pkgbuf.size() >= len)
			{
				string packet = pkgbuf.substr(4, len - 4);
				pkgbuf = pkgbuf.substr(len);
				try
				{
					doPackge(packet);
				}
				catch (const exception& e)
				{
					printf("doPackge error:%s\n", e.what());
				}
			}
			else
			{
				break;
			}
		}
		printf("close recive buf size:%ld\n",buf->len);
	};
	// 启动服务器
	cli.start();
	// 检查是否启动成功
	bool is_connected = Common::waitUntil(5000, [this]() -> bool
		{ return cli.channel->isConnected(); });
	if (!is_connected)
	{
		cli.stop();
		throw std::runtime_error("connect to qq server error:timeout");
	}
}


