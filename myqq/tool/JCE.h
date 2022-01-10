#pragma once

#include <string>
#include <vector>
#include <stdint.h>
#include <map>

class JCE
{
public:
	struct JCEStruct
	{
		enum class TYPE
		{
			STR,
			INT,
			VEC,
			INT_MAP,
			STR_MAP,
			U8VEC,
			UNDEF,
			NESTED,
			DOUBLE,
			STRUCT_END
		};
		explicit JCEStruct(const std::string& d,bool is_u8_vec = false)
		{
			this->str_data = d;
			this->type = TYPE::STR;
			if (is_u8_vec)
			{
				this->type = TYPE::U8VEC;
			}
		}
		explicit JCEStruct(int64_t d)
		{
			this->int_data = d;
			this->type = TYPE::INT;
		}
		explicit JCEStruct(const std::vector<JCEStruct> & d)
		{
			this->vec_data = d;
			this->type = TYPE::VEC;
		}
		explicit JCEStruct(const std::map<int64_t, JCEStruct>& d)
		{
			this->int_map = d;
			this->type = TYPE::INT_MAP;
		}
		explicit JCEStruct(const std::map<std::string, JCEStruct>& d)
		{
			this->str_map = d;
			this->type = TYPE::STR_MAP;
		}
		explicit JCEStruct()
		{
			this->type = TYPE::UNDEF;
		}
		explicit JCEStruct(double d)
		{
			this->type = TYPE::UNDEF;
		}
		std::string str_data;
		double double_data = 0;
		int64_t int_data = 0;
		std::vector<JCEStruct> vec_data;
		std::map<int64_t, JCEStruct> int_map;
		std::map<std::string, JCEStruct> str_map;
		TYPE type = TYPE::STR;
	};
public:
	static std::string encodeStruct(const JCEStruct & nested);
	static std::string encodeWrapper(const JCEStruct& mmap, const std::string& servant, const std::string& func, uint32_t reqid = 0);
	static JCE::JCEStruct decodeWrapper(const std::string& blob);
private:
	static std::string encode(const JCEStruct & obj);
	static JCE::JCEStruct decode(const std::string& encoded);
	static JCEStruct encodeNested(const JCEStruct& obj);
};