#pragma once

#include <stdint.h>
#include <functional>
#include <string>

class Common
{
public:
	static bool waitUntil(int64_t milliseconds, const std::function<bool(void)>& fun);
	static void assign(std::string & strbuf,const void * buf,size_t len);
	static void append(std::string& strbuf, const void* buf, size_t len);
	static std::string randomBytes(size_t n);
	static std::string makeMd5(const std::string& buf);
	static uint64_t dateNow();
	static void writeBiniaryFile(const char* biniary_buf, size_t buf_size, const std::string& file_path);
};

