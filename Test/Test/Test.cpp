// Test.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <iostream>
#include "DumpWalker.hpp"

int _tmain(int argc, wchar_t* argv[])
{
	if (argc < 3) {
		std::wcerr << L"Usage:Analyze.exe <dump file> <symbol search path>" << std::endl;
		return 1;
	}

	try {
		unstd::DumpWalker dmpWalker(argv[1], argv[2]);
		unstd::DumpInfo info = dmpWalker.analyze();
		std::wcout << L"System Process Architecture: " << info.sys.processorArchitecture << std::endl;;
		std::wcout << L"System Version: " << info.sys.majorVersion << L"." 
			<< info.sys.minorVersion << L"." << info.sys.BuildNumber << std::endl;
		std::wcout << L"Exception Code: " << info.except.code << std::endl;

		std::wcout << L"Module List:" << std::endl;
		for (auto iter = info.modules.begin(); iter != info.modules.end(); ++iter) {
			std::wcout << iter->moduleName << L"\t" 
				<< iter->version[0] << L"."
				<< iter->version[1] << L"."
				<< iter->version[2] << L"."
				<< iter->version[3] << L"\t" 
				<< iter->loadedModulePath << std::endl;
		}

		std::wcout << L"Exception Stack Trace: " << std::endl;
		for (auto iter = info.stackFrames.begin(); iter != info.stackFrames.end(); ++iter) {
			std::wcout << iter->filename << L":" << iter->line << L"<" << iter->symbolName << L">" << std::endl;
		}

		return 0;
	}
	catch (unstd::DumpWalkingFailedException &e) {
		std::wcerr << L"Dump Analyze Failed, ErrorCode: " << e.errorCode 
			<< L", Windows Error Code: " << e.windowsLastErrorCode << std::endl;

		return e.errorCode;
	}
}

