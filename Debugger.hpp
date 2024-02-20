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

			char* buffer = nullptr;
			int bufferLen = 0;

			bufferLen = (int)ct.R8;
			buffer = new char[bufferLen+1];
			memset(buffer, 0, bufferLen + 1);

			if (!ReadProcessMemory(cpdi.hProcess, (LPCVOID)ct.Rdx, buffer, bufferLen, NULL)) {
				printf_s("ReadProcAddress()\n");
				return FALSE;
			};

			printf_s("Original String : %s \n", buffer);

			for (int i = 0; i < bufferLen; i++) {
				int parsingLen = 'a' - 'A';
				if (buffer[i] > 'a' || buffer[i] < 'z') {
					buffer[i] = buffer[i] - parsingLen;
				};
			};

			printf_s("Parsing String : %s \n", buffer);

			if(!WriteProcessMemory(cpdi.hProcess, (LPVOID)ct.Rdx, buffer, bufferLen, NULL))  {
				printf_s("WriteProcessMemory");
				return FALSE;
			};
			/*memset(buffer, 0, bufferLen + 1);
			if(ReadProcessMemory(cpdi.hProcess, (LPVOID)ct.Rdx, buffer, bufferLen + 1, NULL)) printf_s("readprocess : %s \n", buffer);*/

			free(buffer);


			/*printf_s("Current RIP : %p \n", ct.Rip);
			ct.Rip = (DWORD)this->debugFunc;

			if (!SetThreadContext(cpdi.hThread, &ct)) { 
				printf_s("SetThreadContext()\n"); 
				return FALSE; 
			};*/

			this->dbgStatus = DBG_CONTINUE;

			/*if (!ContinueDebugEvent(de->dwProcessId, de->dwThreadId, DBG_CONTINUE)) {
				printf_s("ContinueDebugEvent() \n"); 
				return FALSE; 
			};*/

			if (!WriteProcessMemory(cpdi.hProcess, (LPVOID)this->debugFunc, &this->originByte, sizeof(BYTE), NULL)) {
				printf_s("WriteProcessMemory()\n"); 
				return FALSE;
			};

		};

		return TRUE;
	};
	// 32bit 버전 함수호출규약이 다름
	/*BOOL OnExceptionDebugEvent2(LPDEBUG_EVENT de) {
		CONTEXT ct;
		PEXCEPTION_RECORD pr;
		pr = &de->u.Exception.ExceptionRecord;

		if (EXCEPTION_BREAKPOINT == pr->ExceptionCode) {
			memset(&ct, 0, sizeof(CONTEXT));
			ct.ContextFlags = CONTEXT_ALL;
			if (!GetThreadContext(cpdi.hThread, &ct)) ErrorMessage("GetThradContext");

			DWORD readByte = 0, readByte2 = 0;
			ReadProcessMemory(cpdi.hProcess, (LPCVOID)(ct.Rsp + 0x8), &readByte, sizeof(DWORD), NULL);
			ReadProcessMemory(cpdi.hProcess, (LPVOID)(ct.Rsp + 0xC), &readByte2, sizeof(DWORD), NULL);

			PBYTE lpBuffer;
			lpBuffer = (PBYTE)malloc(readByte2 + 1);
			memset(lpBuffer, 0, readByte2 + 1);

			ReadProcessMemory(cpdi.hProcess, (LPVOID)readByte, lpBuffer, readByte2, NULL);
			printf_s("\n#### orginal string : %s \n", lpBuffer);

			for (int i = 0; i < readByte2; i++) {
				if (0x61 <= lpBuffer[i] && lpBuffer[i] <= 0x7A) {
					lpBuffer[i] -= 0x20;
				};
			};

			printf_s("\n### converted string: %s\n", lpBuffer);
			WriteProcessMemory(cpdi.hProcess, (LPVOID)readByte, lpBuffer, readByte2, NULL);

			free(lpBuffer);
			ct.Rip = (DWORD)this->debugFunc;
			SetThreadContext(cpdi.hThread, &ct);

			ContinueDebugEvent(de->dwProcessId, de->dwThreadId, DBG_CONTINUE);
			Sleep(0);

			WriteProcessMemory(cpdi.hProcess, this->debugFunc, &this->originByte, sizeof(BYTE), NULL);
			return TRUE;
		};

		return FALSE;
	};*/

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