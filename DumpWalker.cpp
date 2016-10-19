#include "DumpWalker.hpp"

namespace unstd {
	static DWORD SymbolProcess = 0;
	DumpWalker::DumpWalker(const std::wstring &dumpfile, 
		const std::wstring &symbolSearchPath) 
		: _dumpFilePath(dumpfile), 
		_symbolSearchPath(symbolSearchPath), 
		_openned(false), 
		_dumpFileHandle(NULL), 
		_dumpFileMappingHandle(NULL), 
		_dumpMemoryPtr(NULL), 
		_symProcess(NULL) {
	}

	DumpWalker::~DumpWalker() {
		if (!_openned) {
			return;
		}

		SymCleanup(_symProcess);

		UnmapViewOfFile(_dumpMemoryPtr);
		CloseHandle(_dumpFileMappingHandle);
		CloseHandle(_dumpFileHandle);
	}

	void DumpWalker::openDumpFile() {
		if (_openned) {
			return;
		}

		if (_dumpFilePath.empty()) {
			throw DumpWalkingFailedException(ERROR_DUMP_FILEPATH_INVALID);
		}

		_dumpFileHandle = CreateFileW(
			_dumpFilePath.c_str(), 
			GENERIC_READ, 
			FILE_SHARE_READ, 
			NULL, 
			OPEN_EXISTING, 
			FILE_ATTRIBUTE_NORMAL, 
			NULL);
		if (_dumpFileHandle == INVALID_HANDLE_VALUE) {
			throw DumpWalkingFailedException(ERROR_DUMP_FILEPATH_INVALID, GetLastError());
		}

		_dumpFileMappingHandle = CreateFileMappingW(
			_dumpFileHandle, 
			NULL, 
			PAGE_READONLY, 
			0, 
			0, 
			NULL);
		if (_dumpFileMappingHandle == NULL) {
			throw DumpWalkingFailedException(ERROR_CREATE_DUMP_FILE_MAPPING, GetLastError());
		}

		_dumpMemoryPtr = MapViewOfFile(_dumpFileMappingHandle, FILE_MAP_READ, 0, 0, 0);
		if (_dumpMemoryPtr == NULL) {
			throw DumpWalkingFailedException(ERROR_MAP_DUMP_FILE_MEMORY, GetLastError());
		}

		_openned = true;
	}

	void DumpWalker::initializeSymbol() {
		DWORD opt = SYMOPT_EXACT_SYMBOLS 
			| SYMOPT_FAIL_CRITICAL_ERRORS 
			| SYMOPT_LOAD_LINES 
			| SYMOPT_UNDNAME;
		SymSetOptions(opt);

		_symProcess = (HANDLE)++SymbolProcess;
		if (SymInitializeW(_symProcess, _symbolSearchPath.c_str(), FALSE) == FALSE) {
			throw DumpWalkingFailedException(ERROR_INITIALIZE_SYMBOL, GetLastError());
		}
	}

	DumpSystemInfo DumpWalker::readSystemInfo() {
		MINIDUMP_DIRECTORY *md = NULL;
		MINIDUMP_SYSTEM_INFO *sys = NULL;
		ULONG size = 0;
		if (MiniDumpReadDumpStream(_dumpMemoryPtr, SystemInfoStream, &md, (PVOID *)&sys, &size) == FALSE 
			|| size < sizeof(MINIDUMP_SYSTEM_INFO)) {
				throw DumpWalkingFailedException(ERROR_READ_SYSTEM_INFO);
		}

		DumpInfo::SystemInfo sysInfo;
		sysInfo.processorArchitecture = sys->ProcessorArchitecture;
		sysInfo.majorVersion = sys->MajorVersion;
		sysInfo.minorVersion = sys->MinorVersion;
		sysInfo.BuildNumber = sys->BuildNumber;
		sysInfo.servicePackInstalled = strAtRVA(sys->CSDVersionRva);
		return sysInfo;
	}

	std::vector<DumpModuleInfo> DumpWalker::readModuleInfo() {
		MINIDUMP_DIRECTORY *md = NULL;
		ULONG size = 0;
		MINIDUMP_MODULE_LIST *moduleList = NULL;
		if (MiniDumpReadDumpStream(_dumpMemoryPtr, ModuleListStream, &md, (PVOID *)&moduleList, &size) == FALSE 
			|| size < sizeof(MINIDUMP_MODULE_LIST)) {
				throw DumpWalkingFailedException(ERROR_READ_MODUL_LIST);
		}

		std::vector<DumpModuleInfo> modules;
		modules.reserve(moduleList->NumberOfModules);
		for (ULONG32 i = 0; i < moduleList->NumberOfModules; ++i) {
			MINIDUMP_MODULE m = moduleList->Modules[i];
			DumpModuleInfo dmi;
			dmi.baseAddress = m.BaseOfImage;
			dmi.imageSize = m.SizeOfImage;
			dmi.modulePath = strAtRVA(m.ModuleNameRva);
			auto pos = dmi.modulePath.rfind('\\');
			if (pos != std::wstring::npos) {
				dmi.moduleName = dmi.modulePath.substr(pos + 1);
			}
			dmi.version[0] = HIWORD(m.VersionInfo.dwProductVersionMS);
			dmi.version[1] = LOWORD(m.VersionInfo.dwProductVersionMS);
			dmi.version[2] = HIWORD(m.VersionInfo.dwProductVersionLS);
			dmi.version[3] = LOWORD(m.VersionInfo.dwProductVersionLS);

			SymLoadModuleExW(_symProcess, NULL, dmi.modulePath.c_str(), 
				NULL, dmi.baseAddress, dmi.imageSize, NULL, 0);

			IMAGEHLP_MODULEW64 im64;
			memset(&im64, 0, sizeof(IMAGEHLP_MODULEW64));
			im64.SizeOfStruct = sizeof(IMAGEHLP_MODULEW64);
			if (SymGetModuleInfoW64(_symProcess, dmi.baseAddress, &im64)) {
				dmi.readModuleInfoSuccess = true;
				dmi.baseAddress = im64.BaseOfImage;
				dmi.imageSize = im64.ImageSize;
				dmi.timestampMatched = im64.TimeDateStamp == m.TimeDateStamp;
				dmi.loadedModulePath = im64.LoadedImageName;
				dmi.moduleName = im64.ModuleName;
				dmi.loadedPdbPath = im64.LoadedPdbName;
				dmi.lineNumbersAvailable = im64.LineNumbers == TRUE;
				dmi.symbolInfoAvailable = im64.GlobalSymbols == TRUE;
				dmi.checkSumMatched = im64.CheckSum == m.CheckSum;
			}

			modules.push_back(dmi);
		}

		return modules;
	}

	void DumpWalker::analyze() {
		openDumpFile();
		initializeSymbol();

		auto sys = readSystemInfo();
		auto modules = readModuleInfo();
	}
}