#ifndef OSCROSS_HPP
#define OSCROSS_HPP
#ifdef _WIN32
#include <windows.h>
#define DEBUG_OUTPUT(str) OutputDebugStringA(str)
#define SAFE_SPRINTF sprintf_s
#elif defined(__APPLE__)
#include <os/log.h>
#define DEBUG_OUTPUT(str) os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_DEBUG, "%{public}s", str)
#define SAFE_SPRINTF snprintf
#else
#define DEBUG_OUTPUT(str) printf("%s", str)
#define SAFE_SPRINTF snprintf
#endif
#endif // OSCROSS_HPP