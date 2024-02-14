#pragma once

#include <Windows.h>
#include <iostream>

class DEBUGER {
private:
	DWORD processPID = 0;

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

public:
	DEBUGER(int pid) {
		this->processPID = pid;
	};

	int GetPIDSetting() {
		return this->processPID;
	};

	BOOL SetDebuging() {
		DebugActiveProcess(this->processPID);
	};

}debuger;