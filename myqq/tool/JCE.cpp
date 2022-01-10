#include "JCE.h"

#include <stdexcept>
#include <vector>
#include "./Writer.h"
#include "./Reader.h"

const int TYPE_INT8 = 0;
const int TYPE_INT16 = 1;
const int TYPE_INT32 = 2;
const int TYPE_INT64 = 3;
const int TYPE_FLOAT = 4;
const int TYPE_DOUBLE = 5;
const int TYPE_STRING1 = 6;
const int TYPE_STRING4 = 7;
const int TYPE_MAP = 8;
const int TYPE_LIST = 9;
const int TYPE_STRUCT_BEGIN = 10;
const int TYPE_STRUCT_END = 11;
const int TYPE_ZERO = 12;
const int TYPE_SIMPLE_LIST = 13;


const int TAG_MAP_K = 0;
const int TAG_MAP_V = 1;
const int TAG_LIST_E = 0;
const int TAG_BYTES = 0;
const int TAG_LENGTH = 0;
const int TAG_STRUCT_END = 0;

static std::string createElement(int64_t tag, const JCE::JCEStruct& value);

std::string JCE::encodeStruct(const JCEStruct& nested)
{
	return JCE::encode(JCEStruct(std::vector<JCEStruct>{ JCE::encodeNested(nested) }));
}

std::string JCE::encodeWrapper(const JCEStruct& mmap, const std::string& servant, const std::string& func, uint32_t reqid)
{
	JCEStruct s = JCEStruct(std::vector<JCEStruct>({ mmap }));
	std::string d = JCE::encode(s);
	return JCE::encode(
		JCEStruct({
			JCEStruct(),
			JCEStruct((int64_t)3),
			JCEStruct((int64_t)0),
			JCEStruct((int64_t)0),
			JCEStruct((int64_t)reqid),
			JCEStruct(servant),
			JCEStruct(func),
			JCEStruct(d,true),
			JCEStruct((int64_t)0),
			JCEStruct(std::map<int64_t,JCEStruct>()),
			JCEStruct(std::map<int64_t,JCEStruct>())
			}));
}

static JCE::JCEStruct getFirstJCEStruct(const JCE::JCEStruct & mmap)
{
	if (mmap.type == JCE::JCEStruct::TYPE::INT_MAP)
	{
		for (auto& it : mmap.int_map)
		{
			return it.second;
		}
	}else
	if (mmap.type == JCE::JCEStruct::TYPE::STR_MAP)
	{
		for (auto& it : mmap.str_map)
		{
			return it.second;
		}
	}
	throw std::runtime_error("Error in getFirstJCEStruct");
}
static void readElement(const std::string& readable, int64_t& tag, JCE::JCEStruct& value, int64_t& offset);
JCE::JCEStruct JCE::decodeWrapper(const std::string& blob)
{
	JCE::JCEStruct wrapper = JCE::decode(blob);
	JCE::JCEStruct mmap_decode = JCE::decode(wrapper.int_map.at(7).str_data);
	JCE::JCEStruct mmap = mmap_decode.int_map.at(0);
	JCE::JCEStruct nested = getFirstJCEStruct(mmap);
	if (nested.type != JCEStruct::TYPE::U8VEC)
	{
		nested = getFirstJCEStruct(nested);
	}
	return JCE::decode(nested.str_data).int_map.at(0);
}


static std::string createHead(int64_t type, int64_t tag)
{
	if (tag < 15)
	{
		return std::string(1, (((uint8_t)tag) << 4) | ((uint8_t)type));
	}
	else if (tag < 256)
	{
		std::string ret(2, '\0');
		ret[0] = (0xf0 | ((uint8_t)type));
		ret[1] = (uint8_t)tag;
		return ret;
	}
	else
	{
		throw std::logic_error("Jce tag must be less than 256, received: " + std::to_string(tag));
	}
}

static std::string createBody(int type, const JCE::JCEStruct& value)
{
	if (type == TYPE_INT8)
	{
		return Writer().writeU8((uint8_t)value.int_data).read();
	}
	else if (type == TYPE_INT16)
	{
		return Writer().writeU16((uint16_t)value.int_data).read();
	}
	else if (type == TYPE_INT32)
	{
		return Writer().writeU32((uint32_t)value.int_data).read();
	}
	else if (type == TYPE_INT64)
	{
		return Writer().writeU64((uint64_t)value.int_data).read();
	}
	else if (type == TYPE_FLOAT)
	{
		throw std::logic_error("Jce unsupported float");
	}
	else if (type == TYPE_DOUBLE)
	{
		return Writer().writeDouble(value.double_data).read();
	}
	else if (type == TYPE_STRING1)
	{
		return Writer().writeU8((uint8_t)value.str_data.size()).writeBytes(value.str_data).read();
	}
	else if (type == TYPE_STRING4)
	{
		return Writer().writeU32(value.str_data.size()).writeBytes(value.str_data).read();
	}
	else if (type == TYPE_MAP)
	{
		int64_t n = 0;
		std::string body;
		if (value.type == JCE::JCEStruct::TYPE::STR_MAP)
		{
			for (auto& i : value.str_map)
			{
				++n;
				body.append(createElement(TAG_MAP_K, JCE::JCEStruct(i.first)));
				body.append(createElement(TAG_MAP_V, i.second));
			}
			body = createElement(TAG_LENGTH, JCE::JCEStruct(n)) + body;
			return body;
		}
		else if (value.type == JCE::JCEStruct::TYPE::INT_MAP)
		{
			for (auto& i : value.int_map)
			{
				++n;
				body.append(createElement(TAG_MAP_K, JCE::JCEStruct(i.first)));
				body.append(createElement(TAG_MAP_V, i.second));
			}
			body = createElement(TAG_LENGTH, JCE::JCEStruct(n)) + body;
			return body;
		}
		else
		{
			throw std::logic_error("Jce unsupported map type");
		}	
	}
	else if (type == TYPE_LIST)
	{
		std::string body;
		body.append(createElement(TAG_LENGTH, JCE::JCEStruct((int64_t)value.vec_data.size())));
		for (size_t i = 0; i < value.vec_data.size(); ++i) {
			body.append(createElement(TAG_LIST_E, value.vec_data[i]));
		}
		return body;
	}
	else if (type == TYPE_ZERO)
	{
		return "";
	}
	else if (type == TYPE_SIMPLE_LIST)
	{
		std::string body;
		body.append(createHead(0, TAG_BYTES));
		body.append(createElement(TAG_LENGTH, JCE::JCEStruct((int64_t)value.str_data.size())));
		
		body.append(value.str_data);
		return body;
	}
	else
	{
		throw std::logic_error("Jce Type must be 0 ~ 13, received:" + std::to_string(type));
	}
}



static std::string createElement(int64_t tag, const JCE::JCEStruct& value)
{
	int type;
	if (value.type == JCE::JCEStruct::TYPE::NESTED)
	{
		std::string begin = createHead(TYPE_STRUCT_BEGIN, tag);
		std::string end = createHead(TYPE_STRUCT_END, TAG_STRUCT_END);
		return begin + value.str_data + end;
	}
	if (value.type == JCE::JCEStruct::TYPE::STR)
	{
		if (value.str_data.size() < 0xff)
		{
			type = TYPE_STRING1;
		}
		else
		{
			type = TYPE_STRING4;
		}
	}
	else if (value.type == JCE::JCEStruct::TYPE::VEC || 
		value.type == JCE::JCEStruct::TYPE::STR_MAP||
		value.type == JCE::JCEStruct::TYPE::INT_MAP||
		value.type == JCE::JCEStruct::TYPE::U8VEC)
	{
		if (value.type == JCE::JCEStruct::TYPE::U8VEC) 
		{
			type = TYPE_SIMPLE_LIST;
		}
		else
		{
			type = ((value.type == JCE::JCEStruct::TYPE::VEC)? TYPE_LIST : TYPE_MAP);
		}
	}
	else if (value.type == JCE::JCEStruct::TYPE::INT)
	{
		int64_t n = value.int_data;
		if (n == 0)
			type = TYPE_ZERO;
		else if (n >= -0x80 && n <= 0x7f)
			type = TYPE_INT8;
		else if (n >= -0x8000 && n <= 0x7fff)
			type = TYPE_INT16;
		else if (n >= -0x80000000d && n <= 0x7fffffff)
			type = TYPE_INT32;
		else
			type = TYPE_INT64;
	}
	else if (value.type == JCE::JCEStruct::TYPE::DOUBLE)
	{
		type = TYPE_DOUBLE;
	}
	else
	{
		throw std::logic_error("Jce unsupported type:" + std::to_string((int)value.type));
	}
	std::string head = createHead(type, tag);
	std::string body = createBody(type, value);
	return head + body;
}

std::string JCE::encode(const JCEStruct & obj)
{
	std::vector<std::string> elements;
	if (obj.type == JCEStruct::TYPE::VEC)
	{
		for (size_t tag = 0;tag < obj.vec_data.size();++tag)
		{
			if (obj.vec_data[tag].type == JCEStruct::TYPE::UNDEF)
				continue;
			auto a = obj.vec_data[tag];
			std::string b = createElement(tag, obj.vec_data[tag]);
			elements.push_back(b);
		}
	}
	else if(obj.type == JCEStruct::TYPE::INT_MAP)
	{
		for (auto& i : obj.int_map)
		{
			if (i.second.type == JCEStruct::TYPE::UNDEF)
				continue;
			elements.push_back(createElement((int64_t)i.first, i.second));
		}
	}
	else
	{
		throw std::logic_error("jce encode obj not array or intobj");
	}
	std::string out;
	for (std::string & t : elements)
	{
		out.append(t);
	}
	return out;
}

static void readHead(const std::string& readable, int64_t& tag, int64_t& type, int64_t& offset)
{
	uint8_t head = Reader::readUInt8(readable, offset);
	offset += 1;
	type = head & 0xf;
	tag = ((head & 0xf0) >> 4);
	if (tag == 0xf)
	{
		tag = Reader::readUInt8(readable, offset);
		offset += 1;
	}
}


static JCE::JCEStruct readStruct(const std::string & readable,int64_t & offset)
{
	JCE::JCEStruct mmap;
	mmap.type = JCE::JCEStruct::TYPE::INT_MAP;
	int64_t t;
	JCE::JCEStruct v;
	while (offset < readable.size())
	{
		readElement(readable, t, v, offset);
		if (v.type == JCE::JCEStruct::TYPE::STRUCT_END)
		{
			return mmap;
		}
		else
		{
			mmap.int_map[t] = v;
		}
	}
	throw std::runtime_error("readStruct to the end");
}
static JCE::JCEStruct readBody(const std::string& readable, int64_t type, int64_t& offset)
{
	if (type == TYPE_ZERO)
	{
		return JCE::JCEStruct((int64_t)0);
	}
	else if (type == TYPE_INT8)
	{
		uint8_t t = Reader::readUInt8(readable, offset);
		offset += 1;
		return JCE::JCEStruct((int64_t)t);
	}
	else if (type == TYPE_INT16)
	{
		uint16_t t = Reader::readUInt16BE(readable, offset);
		offset += 2;
		return JCE::JCEStruct((int64_t)t);
	}
	else if (type == TYPE_INT32)
	{
		uint32_t t = Reader::readUInt32BE(readable, offset);
		offset += 4;
		return JCE::JCEStruct((int64_t)t);
	}
	else if (type == TYPE_INT64)
	{
		uint64_t t = Reader::readUInt64BE(readable, offset);
		offset += 8;
		return JCE::JCEStruct((int64_t)t);
	}
	else if (type == TYPE_STRING1)
	{
		int64_t len = Reader::readUInt8(readable, offset);
		offset += 1;
		if (len > 0)
		{
			std::string t = readable.substr(offset, len);
			offset += len;
			return JCE::JCEStruct(t);
		}
		else
		{
			return JCE::JCEStruct(std::string());
		}
	}
	else if (type == TYPE_STRING4)
	{
		int64_t len = Reader::readUInt32BE(readable, offset);
		offset += 4;
		if (len > 0)
		{
			std::string t = readable.substr(offset, len);
			offset += len;
			return JCE::JCEStruct(t);
		}
		else
		{
			return JCE::JCEStruct(std::string());
		}
	}
	else if (type == TYPE_SIMPLE_LIST)
	{
		int64_t t1, t2;
		JCE::JCEStruct v;
		readHead(readable, t1, t2, offset);
		readElement(readable, t1, v, offset);
		if (v.type != JCE::JCEStruct::TYPE::INT)
		{
			throw std::runtime_error("the len type(TYPE_SIMPLE_LIST) int not int");
		}
		int64_t len = v.int_data;
		if (len > 0)
		{
			std::string t = readable.substr(offset, len);
			offset += len;
			return JCE::JCEStruct(t,true);
		}
		else
		{
			return JCE::JCEStruct(std::string(),true);
		}
	}
	else if (type == TYPE_LIST)
	{
		int64_t t1;
		JCE::JCEStruct v;
		readElement(readable, t1, v, offset);
		if (v.type != JCE::JCEStruct::TYPE::INT)
		{
			throw std::runtime_error("the len type(TYPE_LIST) int not int");
		}
		int64_t len = v.int_data;
		std::vector<JCE::JCEStruct> lst;
		for (int64_t i = 0;i < len;++i)
		{
			readElement(readable, t1, v, offset);
			lst.push_back(v);
		}
		return JCE::JCEStruct(lst);
	}
	else if (type == TYPE_MAP)
	{
		int64_t t1;
		JCE::JCEStruct v;
		readElement(readable, t1, v, offset);
		if (v.type != JCE::JCEStruct::TYPE::INT)
		{
			throw std::runtime_error("the len type(TYPE_LIST) int not int");
		}
		int64_t len = v.int_data;
		JCE::JCEStruct mmap;
		mmap.type = JCE::JCEStruct::TYPE::STR_MAP;
		for (int64_t i = 0;i < len;++i)
		{
			JCE::JCEStruct k, v;
			readElement(readable, t1, k, offset);
			if (k.type != JCE::JCEStruct::TYPE::STR)
			{
				throw std::runtime_error("the map key type not str");
			}
			readElement(readable, t1, v, offset);
			mmap.str_map[k.str_data] = v;
		}
		return JCE::JCEStruct(mmap);
	}
	else if (type == TYPE_STRUCT_BEGIN)
	{
		return readStruct(readable, offset);
	}
	else if (type == TYPE_STRUCT_END)
	{
		JCE::JCEStruct t;
		t.type = JCE::JCEStruct::TYPE::STRUCT_END;
		return t;
	}
	else if (type == TYPE_FLOAT)
	{
		uint32_t f = Reader::readUInt32BE(readable, offset);
		offset += 4;
		float fnum;
		memcpy_s(&fnum, 4, &f, 4);
		JCE::JCEStruct j;
		j.double_data = fnum;
		j.type = JCE::JCEStruct::TYPE::DOUBLE;
		return j;
	}
	else if (type == TYPE_DOUBLE)
	{
		uint64_t f = Reader::readUInt64BE(readable, offset);
		offset += 8;
		double dnum;
		memcpy_s(&dnum, 8, &f, 8);
		JCE::JCEStruct j;
		j.double_data = dnum;
		j.type = JCE::JCEStruct::TYPE::DOUBLE;
		return j;
	}
	else
	{
		throw  std::runtime_error("unknown jce type: " + std::to_string(type));
	}
}

static void readElement(const std::string& readable, int64_t& tag, JCE::JCEStruct& value, int64_t& offset)
{
	int64_t type;
	readHead(readable, tag, type, offset);
	value = readBody(readable, type, offset);
}

JCE::JCEStruct JCE::decode(const std::string& encoded)
{
	JCE::JCEStruct decoded;
	decoded.type = JCEStruct::TYPE::INT_MAP;
	int64_t tag;
	JCE::JCEStruct value;
	int64_t offset = 0;
	while (offset < encoded.size())
	{
		readElement(encoded, tag, value, offset);
		decoded.int_map[tag] = value;
	}
	return decoded;
}

JCE::JCEStruct JCE::encodeNested(const JCEStruct& obj)
{
	std::string en = JCE::encode(obj);
	
	JCEStruct j(en);
	j.type = JCEStruct::TYPE::NESTED;
	return j;
}
