// Test.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <iostream>
#include "DumpWalker.hpp"

int _tmain(int argc, wchar_t* argv[])
{
	if (argc < 3) {
		printf("Usage:Analyze.exe <dump file> <symbol search path>");
		return 1;
	}

	try {
		unstd::DumpWalker dmpWalker(argv[1], argv[2]);
		dmpWalker.analyze();
		return 0;
	}
	catch (unstd::DumpWalkingFailedException &e) {
		std::cerr << "Dump Analyze Failed, ErrorCode: " << e.errorCode 
			<< ", Windows Error Code: " << e.windowsLastErrorCode << std::endl;

		return e.errorCode;
	}
}

