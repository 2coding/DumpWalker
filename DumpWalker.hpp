#pragma once
#include <string>
#include <exception>
#include <vector>
#include <Windows.h>
#include <DbgHelp.h>

#pragma comment(lib, "Dbghelp.lib")

namespace unstd {
	const DWORD ERROR_DUMP_FILEPATH_INVALID = 1;
	const DWORD ERROR_CREATE_DUMP_FILE_MAPPING = 2;
	const DWORD ERROR_MAP_DUMP_FILE_MEMORY = 3;
	const DWORD ERROR_INITIALIZE_SYMBOL = 4;
	const DWORD ERROR_READ_SYSTEM_INFO = 5;
	const DWORD ERROR_READ_MODUL_LIST = 6;

	class DumpWalkingFailedException : public std::exception {
	public:
		DumpWalkingFailedException(DWORD error, DWORD lastErrorCode = ERROR_SUCCESS) 
			: exception(), 
			errorCode(error), 
			windowsLastErrorCode(lastErrorCode) {}

		DWORD errorCode;
		DWORD windowsLastErrorCode;
	};

	class DumpInfo {
	public:
		struct SystemInfo {
			USHORT processorArchitecture;

			ULONG32 majorVersion;
			ULONG32 minorVersion;
			ULONG32 BuildNumber;

			std::wstring servicePackInstalled;
		};

		struct ModuleInfo {
			ModuleInfo() {
				baseAddress = 0;
				imageSize = 0;
				timestampMatched = false;
				lineNumbersAvailable = false;
				symbolInfoAvailable = false;
				checkSumMatched = false;
				readModuleInfoSuccess = false;
				memset(&version, 0, sizeof(version));
			}

			ULONG64 baseAddress;
			ULONG32 imageSize;
			std::wstring modulePath;
			std::wstring moduleName;
			std::wstring loadedModulePath;
			std::wstring loadedPdbPath;
			bool readModuleInfoSuccess;
			bool timestampMatched;
			bool lineNumbersAvailable;
			bool symbolInfoAvailable;
			bool checkSumMatched;
			WORD version[4];
		};
	public:
		std::wstring dumpFilepath;
	};

	typedef DumpInfo::SystemInfo DumpSystemInfo;
	typedef DumpInfo::ModuleInfo DumpModuleInfo;

	class DumpWalker {
	public:
		DumpWalker(const std::wstring &dumpfile, 
			const std::wstring &symbolSearchPath);
		~DumpWalker();
		void analyze();

	private:
		DumpWalker(const DumpWalker &other) {}
		DumpWalker & operator=(const DumpWalker &other) {
			return *this;
		}

	private:
		void openDumpFile();
		void initializeSymbol();

		DumpSystemInfo readSystemInfo();
		std::vector<DumpModuleInfo> readModuleInfo();

		void *ptrAtRVA(RVA rva) const {
			return (void *)(((LPBYTE)_dumpMemoryPtr) + rva);
		}

		std::wstring strAtRVA(RVA rva) const {
			MINIDUMP_STRING *str = static_cast<MINIDUMP_STRING *>(ptrAtRVA(rva));
			return std::wstring(str->Buffer);
		}

	private:
		std::wstring _dumpFilePath;
		std::wstring _symbolSearchPath;
		bool _openned;

		HANDLE _dumpFileHandle;
		HANDLE _dumpFileMappingHandle;
		void *_dumpMemoryPtr;

		HANDLE _symProcess;

		USHORT _processArchitecture;
	};
}