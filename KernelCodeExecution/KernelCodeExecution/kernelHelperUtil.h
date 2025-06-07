// CallbackRemover.h
#pragma once
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <Psapi.h>
#include <ntstatus.h>
#include <map>
#include "MemHandler.h"

#define PRINT_ERROR_AUTO(func) (wprintf(L"ERROR " TEXT(__FUNCTION__) L" ; " func L" (0x%08x)\n", GetLastError()))

class kernelHelper
{
public:
	kernelHelper(MemHandler* objMemHandler);
	~kernelHelper();
	PVOID lpNtosBase = { 0 };
	bool codeExecution(DWORD32 processPID);
	DWORD64 returnNTBASE();

private:
	PVOID ResolveDriverBase(const wchar_t* strDriverName);
	MemHandler* objMemHandler;
};

