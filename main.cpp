#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

#include "Debugger.hpp"

DWORD FindProcessID(const wchar_t* exeName) {
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	if (snap == NULL) {
		printf_s("CreateToolhelp32Snapshoot() \n");
		return -1;
	};

	PROCESSENTRY32 pe32;
	memset(&pe32, 0, sizeof(PROCESSENTRY32));
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(snap, &pe32)) {
		printf_s("Process32First()\n");
		return -1;
	};

	wchar_t* currentName = nullptr;
	int result = 0;
	while (TRUE) {
		if(snap == NULL) break;
		
		currentName = nullptr;
		currentName = pe32.szExeFile;

		result = _wcsicmp(currentName, exeName);
		if (result == 0 && result != 0xffffffff) {
			printf_s("Sucess to find process\n");
			return pe32.th32ProcessID;
		};

		result = Process32Next(snap, &pe32);
		if (result == FALSE) break;
	};

	printf_s("Failed to find process \n");
	return -1;
};

int main(void) {
	int PID = 0;
	
	PID = FindProcessID(L"notepad.exe");
	if (PID == -1) exit(-1);

	debugger db(PID);
	db.SetModule("kernel32.dll");
	db.SetDebugFunc("WriteFile");
	db.SetDebuging();
	while (1) {
	};

	return 0;
};