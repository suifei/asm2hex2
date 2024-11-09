// printf_wrapper.h
#ifndef PRINTF_WRAPPER_H
#define PRINTF_WRAPPER_H

#include <stddef.h>  // for size_t

#ifdef __cplusplus
extern "C" {
#endif

// printf的替代函数，每次调用会追加到缓冲区
void printf_to_string(const char* format, ...);

// 获取累积的所有字符串结果
const char* get_printf_buffer(void);

// 清空缓冲区
void clear_printf_buffer(void);

// 16进制打印函数
void print_string_hex(const char *comment, unsigned char *str, size_t len);

#ifdef __cplusplus
}
#endif

#endif