#pragma once
#include <Windows.h>
class MemHandler
{
public:
    virtual BOOL VirtualRead(DWORD64 address, void* buffer, size_t bytesToRead) = 0;
    virtual BOOL WriteMemoryDWORD64(DWORD64 Address, DWORD64 Value) = 0;
    virtual BOOL WriteMemoryPrimitive(DWORD Size, DWORD64 Address, DWORD Value) = 0;
};

