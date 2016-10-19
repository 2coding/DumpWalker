#include "DumpWalker.hpp"
#include <map>

namespace unstd {
	std::map<HANDLE, DumpWalker *> DumpWalkerMap;
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
			_symProcess = (HANDLE) ++SymbolProcess;
			DumpWalkerMap[_symProcess] = this;
	}

	DumpWalker::~DumpWalker() {
		DumpWalkerMap[_symProcess] = NULL;

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

	void DumpWalker::readMemoryInfo() {
		MINIDUMP_DIRECTORY *md = NULL;
		ULONG size = 0;
		MINIDUMP_MEMORY_LIST *memoryList = NULL;
		if (MiniDumpReadDumpStream(_dumpMemoryPtr, MemoryListStream, &md, (PVOID *)&memoryList, &size) == FALSE 
			|| size < sizeof(MINIDUMP_MEMORY_LIST)) {
				throw DumpWalkingFailedException(ERROR_READ_MEMORY_LIST);
		}

		_memorys.clear();
		_memorys.reserve(memoryList->NumberOfMemoryRanges);
		for (ULONG32 i = 0; i < memoryList->NumberOfMemoryRanges; ++i) {
			MINIDUMP_MEMORY_DESCRIPTOR m = memoryList->MemoryRanges[i];
			MemoryInfo mi;
			mi.baseAddress = m.StartOfMemoryRange;
			mi.size = m.Memory.DataSize;
			mi.basePtr = static_cast<PBYTE>(ptrAtRVA(m.Memory.Rva));
			_memorys.push_back(mi);
		}
	}

	DumpExceptionInfo DumpWalker::readExcpetionInfo() {
		MINIDUMP_DIRECTORY *md = NULL;
		ULONG size = 0;
		MINIDUMP_EXCEPTION_STREAM *except = NULL;
		if (MiniDumpReadDumpStream(_dumpMemoryPtr, ExceptionStream, &md, (PVOID *)&except, &size) == FALSE 
			|| size < sizeof(MINIDUMP_EXCEPTION_STREAM)) {
				throw DumpWalkingFailedException(ERROR_READ_EXCEPTION_INFO);
		}

		DumpExceptionInfo de;
		de.threadId = except->ThreadId;
		de.code = except->ExceptionRecord.ExceptionCode;
		CONTEXT *ctx = static_cast<CONTEXT *>(ptrAtRVA(except->ThreadContext.Rva));
		memcpy(&de.context, ctx, except->ThreadContext.DataSize);
		return de;
	}

	std::vector<DumpStackFrame> DumpWalker::readStackFrame(const DumpExceptionInfo &except, 
		USHORT processorArchitecture) {
		DWORD machineType = 0; 
		STACKFRAME64 sf64;
		memset(&sf64, 0, sizeof(STACKFRAME64));
		sf64.AddrPC.Mode = AddrModeFlat;  
		sf64.AddrFrame.Mode = AddrModeFlat;  
		sf64.AddrStack.Mode = AddrModeFlat;  
		sf64.AddrBStore.Mode = AddrModeFlat; 
		switch(processorArchitecture)
		{
#ifdef _X86_
		case PROCESSOR_ARCHITECTURE_INTEL: 
			machineType = IMAGE_FILE_MACHINE_I386;
			sf64.AddrPC.Offset = except.context.Eip;    
			sf64.AddrStack.Offset = except.context.Esp;
			sf64.AddrFrame.Offset = except.context.Ebp;
			break;
#endif
#ifdef _AMD64_
		case PROCESSOR_ARCHITECTURE_AMD64:
			machineType = IMAGE_FILE_MACHINE_AMD64;
			sf64.AddrPC.Offset = except.context.Rip;    
			sf64.AddrStack.Offset = except.context.Rsp;
			sf64.AddrFrame.Offset = except.context.Rbp;
			break;
#endif
#ifdef _IA64_
		case PROCESSOR_ARCHITECTURE_AMD64:
			machineType = IMAGE_FILE_MACHINE_IA64;
			sf64.AddrPC.Offset = except.context.StIIP;
			sf64.AddrStack.Offset = except.context.IntSp;
			sf64.AddrFrame.Offset = except.context.RsBSP;    
			sf64.AddrBStore.Offset = except.context.RsBSP;
			break;
#endif 
		default:
			throw DumpWalkingFailedException(ERROR_UNSUPPORT_PLATFORM);
		}

		std::vector<DumpStackFrame> stackFrames;
		do 
		{
			BOOL walk = StackWalk64(machineType, _symProcess, (HANDLE)except.threadId, 
				&sf64, (PVOID)(&except.context), 
				DumpWalker::ReadMemoryRoutine, 
				DumpWalker::FunctionTableAccessRoutine, 
				DumpWalker::GetModuleBaseRoutine, 
				NULL);

			if (walk == FALSE) {
				break;
			}

			DumpStackFrame frame;
			IMAGEHLP_LINEW64 line64;
			line64.SizeOfStruct = sizeof(IMAGEHLP_LINEW64);
			DWORD disp = 0;
			if (SymGetLineFromAddrW64(_symProcess, sf64.AddrPC.Offset, &disp, &line64)) {
				frame.filename = line64.FileName;
				frame.line = line64.LineNumber;
			}

			byte buf[4096] = {0};
			DWORD64 displacement = 0;
			SYMBOL_INFOW *si = (SYMBOL_INFOW *)buf;
			si->SizeOfStruct = sizeof(SYMBOL_INFOW);
			si->MaxNameLen = (sizeof(buf) / sizeof(*buf) - sizeof(SYMBOL_INFO) - 1) / sizeof(*(si->Name));
			if (SymFromAddrW(_symProcess, sf64.AddrPC.Offset, &displacement, si)) {
				frame.symbolName = si->Name;
				frame.offset = displacement;
			}

			if (frame.filename.empty()) {
				continue;;
			}

			stackFrames.push_back(frame);
		} while (true);

		if (stackFrames.empty()) {
			throw DumpWalkingFailedException(ERRPR_STACK_FRAME_EMPTY);
		}

		return stackFrames;
	}

	BOOL DumpWalker::ReadMemoryRoutine(HANDLE hProcess, DWORD64 lpBaseAddress, 
		PVOID lpBuffer, DWORD nSize, LPDWORD lpNumberOfBytesRead) {
			if (lpBuffer == NULL || nSize == 0 || lpNumberOfBytesRead == NULL) {
				return FALSE;
			}

			auto fnd = DumpWalkerMap.find(hProcess);
			if (fnd == DumpWalkerMap.end()) {
				return FALSE;
			}

			DumpWalker *walker = fnd->second;
			return walker->readMemory(lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
	}

	BOOL DumpWalker::readMemory(DWORD64 baseAddr, PVOID buffer, DWORD size, LPDWORD readSize) {
		for (auto iter = _memorys.begin(); iter != _memorys.end(); ++iter) {
			if (baseAddr < iter->baseAddress || baseAddr >= iter->baseAddress + iter->size) {
				continue;
			}

			DWORD offset = (DWORD)(baseAddr - iter->baseAddress);
			DWORD sz = size;
			if (offset + sz > iter->size) {
				sz = iter->size - offset;
			}

			if (sz == 0) {
				return FALSE;
			}

			memcpy(buffer, iter->basePtr + offset, sz);
			*readSize = sz;
			return TRUE;
		}

		return FALSE;
	}

	DumpInfo DumpWalker::analyze() {
		openDumpFile();
		initializeSymbol();

		DumpInfo dump;
		dump.dumpFilepath = _dumpFilePath;
		dump.sys = readSystemInfo();
		dump.modules = readModuleInfo();
		readMemoryInfo();
		dump.except = readExcpetionInfo();
		dump.stackFrames = readStackFrame(dump.except, dump.sys.processorArchitecture);

		return dump;
	}
}