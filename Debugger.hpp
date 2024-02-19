#pragma once

#include <Windows.h>
#include <iostream>

typedef class DEBUGGER {
private:
	DWORD processPID = 0;
	HANDLE debuggingThreadHandle = NULL;
	DEBUG_EVENT de;
	DWORD dbgStatus = 0;
	HMODULE moduleHandle = NULL;
	CREATE_PROCESS_DEBUG_INFO cpdi;
	FARPROC debugFunc;
	//char* debugFuncName;
	BYTE originByte = 0;
	const BYTE setDebugOn = 0xCC;
	

	void ErrorMessage(const char* msg) {
		MessageBoxA(NULL, msg, "ERROR", NULL);
		exit(-1);
	};

	BOOL SetProcess(int pid) {
		if (pid < 0) {
			printf_s("pid is wrong \n");
			return FALSE;
		};
		this->processPID = pid;
	};

	BOOL OnCreateProcessDebugEvent(LPDEBUG_EVENT de) {
		if (moduleHandle == NULL) {
			printf_s("Module is Avalid\n");
			return FALSE;
		};

		if (debugFunc == NULL) {
			printf_s("debugFunc is Avalid\n");
			return FALSE;
		};

		memcpy(&cpdi, &de->u.CreateProcessInfo, sizeof(CREATE_PROCESS_DEBUG_INFO));
		if (!ReadProcessMemory(cpdi.hProcess, debugFunc, &originByte, sizeof(BYTE), NULL)) ErrorMessage("ReadProcessMemory");
		if (!WriteProcessMemory(cpdi.hProcess, debugFunc, &setDebugOn, sizeof(BYTE), NULL)) ErrorMessage("WriteProcessMemory");

		return TRUE;
	};

	BOOL OnExceptionDebugEvent(LPDEBUG_EVENT de) {
		CONTEXT ct;
		PEXCEPTION_RECORD pr;
		pr = &de->u.Exception.ExceptionRecord;

		if (EXCEPTION_BREAKPOINT== pr->ExceptionCode) {
			memset(&ct, 0, sizeof(CONTEXT));
			ct.ContextFlags = CONTEXT_ALL;
			if (!GetThreadContext(cpdi.hThread, &ct)) ErrorMessage("GetThradContext");

			DWORD readByte = 0, readByte2 = 0;
			BYTE bytes = 0;
			ReadProcessMemory(cpdi.hProcess, (LPCVOID)(ct.Rsp + 0x8), &readByte, sizeof(DWORD), NULL);
			printf_s("rsp + 8 : %p \n", readByte);
			ReadProcessMemory(cpdi.hProcess, (LPVOID)(ct.Rsp + 0xC), &readByte2, sizeof(DWORD), NULL);
			printf_s("rsp + c : %p \n", readByte2);
			printf_s("r9 : %p \n", ct.R9);
			int i = 0;

			while (TRUE) {
				if (!ReadProcessMemory(cpdi.hProcess, (LPVOID)(ct.Rsp + i++), &bytes, sizeof(BYTE), NULL)) {
					printf_s("ReadProcess!\n");
						break;
				};
				if (bytes == NULL) {
					break;
				};
				printf_s("%c \n", bytes);
			};
		};

		return TRUE;
	};

	static DWORD WINAPI DebuggingThreadProc(LPVOID arg) {
		DEBUGGER* db = (DEBUGGER*)arg;

		auto result = DebugActiveProcess(db->processPID);
		if (!result) {
			printf_s("DebugActiveProcess()\n");
			return -1;
		};
		
		while (TRUE) {
			if (WaitForDebugEvent(&db->de, INFINITE)) {
				switch (db->de.dwDebugEventCode) {
				case CREATE_PROCESS_DEBUG_EVENT:
					if (!db->OnCreateProcessDebugEvent(&db->de)) db->ErrorMessage("OnCreateProcessDebugEvent()");
					db->dbgStatus = DBG_CONTINUE;
					break;
				case CREATE_THREAD_DEBUG_EVENT:
					break;
				case EXCEPTION_DEBUG_EVENT:
					if (db->de.u.Exception.ExceptionRecord.ExceptionAddress != db->debugFunc) {
						db->dbgStatus = DBG_EXCEPTION_NOT_HANDLED;
						break;
					};
					if (!db->OnExceptionDebugEvent(&db->de)) db->ErrorMessage("OnExceptionDebugEvent()");
					
					break;
				case EXIT_PROCESS_DEBUG_EVENT:
					break;
				case EXIT_THREAD_DEBUG_EVENT:
					break;
				case LOAD_DLL_DEBUG_EVENT:
					break;
				case OUTPUT_DEBUG_STRING_EVENT:
					break;
				case RIP_EVENT:
					break;
				case UNLOAD_DLL_DEBUG_EVENT:
					break;
				default:
					break;
				};

				ContinueDebugEvent(db->de.dwProcessId, db->de.dwThreadId, db->dbgStatus);
			};

		};

		return 0;
	};

public:
	DEBUGGER(int pid) {
		this->processPID = pid;
	};

	int GetPIDSetting() {
		return this->processPID;
	};

	BOOL SetModule(const char* moduleName) {
		moduleHandle = LoadLibraryA(moduleName);
		if (moduleHandle == NULL) {
			printf_s("Module Name is wrong \n");
			return FALSE;
		};
		return TRUE;
	};

	HMODULE GetModule() {
		return moduleHandle;
	};

	BOOL SetDebugFunc(const char* debugFuncName) {
		memset(&debugFunc, 0, sizeof(FARPROC));
		debugFunc = GetProcAddress(moduleHandle, debugFuncName);
		if (debugFunc == NULL) {
			printf_s("GetProcAddress() \n");
			return FALSE;
		};
		return TRUE;
	};

	BOOL SetDebuging() {
		if (debuggingThreadHandle != NULL) {
			printf_s("Already Debugging\n");
			return FALSE;
		};

		debuggingThreadHandle = CreateThread(NULL, 0, DebuggingThreadProc, this, 0, NULL);
		if (debuggingThreadHandle == NULL) {
			printf_s("CreateThread() \n");
			return FALSE;
		};

		return TRUE;
	};
}debugger;