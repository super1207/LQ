#pragma once

#include <string>

class QQTEA
{
public:
    static std::string encode(const std::string &key, const std::string &data);
    static std::string decode(const std::string &key, const std::string &data);
};
