#include <Windows.h>  
#include "wchar.h"
#include "stdio.h" 
#include "atltrace.h"

void PrintError(wchar_t* err_msg) {
	wchar_t printBuf[512];
	wchar_t buf[512];
	FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		buf, (sizeof(buf) / sizeof(wchar_t)), NULL);
	wsprintf(printBuf, L"%wsLastError: %ws", err_msg, buf);
	printf("%S \r\n", printBuf);
}

#define LOG_LAST_ERROR(s) PrintError(s);

#ifdef _WINDLL
#define DbgPrint printf
#else
#define DbgPrint printf
#endif