// Crash.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Windows.h>
#include <DbgHelp.h>
#include <time.h>

#pragma comment(lib, "Dbghelp.lib")

static void writeDump(LPEXCEPTION_POINTERS e) {
	wchar_t dirpath[MAX_PATH] = {0};
	GetModuleFileNameW(NULL, dirpath, sizeof(dirpath) / sizeof(*dirpath));

	wchar_t *pos = wcsrchr(dirpath, '\\');
	if (pos == NULL) {
		return ;
	}
	*pos = 0;

	//time_t now = time(NULL);
	//struct tm tmnow;
	//localtime_s(&tmnow, &now);
	//wchar_t nowstr[MAX_PATH] = {0};
	//wcsftime(nowstr, sizeof(nowstr) / sizeof(*nowstr), L"%Y%m%d-%H%M%S", &tmnow);

	wchar_t filepath[MAX_PATH] = {0};
	//swprintf_s(filepath, L"%s\\Crap_%s.dmp", dirpath, nowstr);
	swprintf_s(filepath, L"%s\\Crap.dmp", dirpath);
	HANDLE hFile = CreateFileW(filepath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return;
	}

	MINIDUMP_EXCEPTION_INFORMATION mei;
	mei.ThreadId = GetCurrentThreadId();
	mei.ExceptionPointers = e;
	mei.ClientPointers = FALSE;
	MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, 
		MiniDumpNormal, &mei, NULL, NULL);
	CloseHandle(hFile);
}

static LONG handleException(LPEXCEPTION_POINTERS e) {
	writeDump(e);
	return EXCEPTION_EXECUTE_HANDLER;
}

static void func4() {
	printf("In %s\r\n", __FUNCTION__);
	do 
	{
		printf("Do you want crash?(Y?N)\r\n");
		char c = getchar();
		if (c == 'y' || c == 'Y') {
			int *p = 0;
			*p = 100;
		}
	} while (true);
}

static void func3() {
	printf("In %s\r\n", __FUNCTION__);
	func4();
}

static void func2() {
	printf("In %s\r\n", __FUNCTION__);
	func3();
}

static void func1() {
	printf("In %s\r\n", __FUNCTION__);
	func2();
}

int _tmain(int argc, _TCHAR* argv[])
{
	__try {
		func1();
		return 0;
	}
	__except(handleException(GetExceptionInformation())) {}
}

