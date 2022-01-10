#include "Common.h"

#include <stdint.h>
#include <thread>
#include <functional>
#include <chrono>
#include <string>
#include <random>
#include <mmd5/mmd5.h>
#include <stdexcept>
#include <fstream>

using namespace std;
using namespace std::this_thread;
using namespace chrono;

bool Common::waitUntil(int64_t milliseconds, const std::function<bool(void)>& fun)
{

    if (milliseconds <= 0)
    {
        return false;
    }
    const auto begin = high_resolution_clock::now();
    while (true)
    {
        sleep_for(chrono::milliseconds(1));
        if (fun())
        {
            return true;
        }
        const auto elapsed = duration_cast<chrono::milliseconds>(high_resolution_clock::now() - begin).count();
        if (elapsed > milliseconds)
        {
            break;
        }
    }
    return false;
}

void Common::assign(std::string& strbuf, const void* buf, size_t len)
{
    strbuf.resize(len);
    memcpy_s((void*)strbuf.data(), len, buf, len);
}

void Common::append(std::string& strbuf, const void* buf, size_t len)
{
    size_t orglen = strbuf.size();
    strbuf.resize(orglen + len);
    memcpy_s((void*)(strbuf.data() + orglen), len, buf, len);
}

string Common::randomBytes(size_t n)
{
    string ret_buf(n, '\0');
    random_device rd;
    uniform_int_distribution<uint32_t> dist(0, UINT8_MAX);
    for (size_t i = 0; i < n; ++i)
        ret_buf[i] = dist(rd);
    return ret_buf;
}

std::string Common::makeMd5(const std::string& buf)
{
    string ret_buf(16, '\0');
    make_md5((const uint8_t*)buf.data(), buf.size(), (uint8_t*)ret_buf.data());
    return ret_buf;
}

uint64_t Common::dateNow()
{
    const auto begin = high_resolution_clock::now();
    return duration_cast<chrono::milliseconds>(begin.time_since_epoch()).count();
}

void Common::writeBiniaryFile(const char* biniary_buf, size_t buf_size, const std::string& file_path)
{
    using namespace std;
    //check is biniary_buf a null pointer
    if (!biniary_buf)
        throw runtime_error("biniary_buf is null");
    ofstream out(file_path, ios::binary);
    if (!out.is_open())
        throw runtime_error("file " + file_path + " can't open");
    out.write(biniary_buf, buf_size);
}
