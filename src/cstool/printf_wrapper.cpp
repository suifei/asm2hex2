// printf_wrapper.cpp
#include "printf_wrapper.h"
#include <sstream>
#include <string>
#include <cstdarg>
#include <vector>

static std::stringstream g_ss;
static std::string g_current_str;

extern "C"
{

    void printf_to_string(const char *format, ...)
    {
        va_list args;
        va_start(args, format);

        va_list args_copy;
        va_copy(args_copy, args);
        int size = vsnprintf(nullptr, 0, format, args_copy);
        va_end(args_copy);

        if (size >= 0)
        {
            std::vector<char> buffer(size + 1);
            vsnprintf(buffer.data(), buffer.size(), format, args);
            g_ss << std::string(buffer.data(), size); // 追加到现有内容
        }

        va_end(args);
    }

    const char *get_printf_buffer()
    {
        g_current_str = g_ss.str(); // 获取累积的所有内容
        return g_current_str.c_str();
    }

    void clear_printf_buffer()
    {
        g_ss.str("");          // 清空缓冲区内容
        g_ss.clear();          // 重置流的状态标志
        g_current_str.clear(); // 清空当前字符串
    }

    
void print_string_hex(const char *comment, unsigned char *str, size_t len)
{
	unsigned char *c;

	printf_to_string("%s", comment);
	for (c = str; c < str + len; c++) {
		printf_to_string("0x%02x ", *c & 0xff);
	}

	printf_to_string("\n");
}
}