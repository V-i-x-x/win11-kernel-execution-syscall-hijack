#include "memory.h"

Memory::Memory()  {
	/* Constructor for Memory Manager */
	// Opens a handle to RTCORE64
    Memory::DriverHandle = CreateFileW(LR"(\\.\RTCore64)", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (Memory::DriverHandle == INVALID_HANDLE_VALUE) {
        printf("Failed to open handle to device\t0x%x\n", GetLastError());
        exit(1);
    }
    else {
        puts("Connected to device");

    }
}

result Memory::ReadMemoryPrimitive(DWORD Size, DWORD64 Address) {
    RTCORE64_MEMORY_READ MemoryRead{};
    MemoryRead.Address = Address;
    MemoryRead.ReadSize = Size;
    struct result resultdata;
    DWORD BytesReturned;

    BOOL response = DeviceIoControl(Memory::DriverHandle,
        RTCORE64_MEMORY_READ_CODE,
        &MemoryRead,
        sizeof(MemoryRead),
        &MemoryRead,
        sizeof(MemoryRead),
        &BytesReturned,
        nullptr);
    // Set the status and value in the result structure
    resultdata.resultstatus = response;  // Set TRUE if successful, FALSE if failed
    resultdata.resultvalue = response ? MemoryRead.Value : 0;  // Set value or 0 if failed
    return resultdata;
}

BOOL Memory::WriteMemoryPrimitive(DWORD Size, DWORD64 Address, DWORD Value) {
    RTCORE64_MEMORY_READ MemoryRead{};
    MemoryRead.Address = Address;
    MemoryRead.ReadSize = Size;
    MemoryRead.Value = Value;

    DWORD BytesReturned;

    BOOL response = DeviceIoControl(Memory::DriverHandle,
        RTCORE64_MEMORY_WRITE_CODE,
        &MemoryRead,
        sizeof(MemoryRead),
        &MemoryRead,
        sizeof(MemoryRead),
        &BytesReturned,
        nullptr);

    return response;
}

BOOL Memory::WriteMemoryDWORD64(DWORD64 Address, DWORD64 Value) {
    BOOL response = false;
    BOOL response2 = false;
    response = WriteMemoryPrimitive(4, Address, Value & 0xffffffff);
    if (response) {
        response2 = WriteMemoryPrimitive(4, Address + 4, Value >> 32);
    }
    else {
        return response;
    }
    return response2;

}

BOOL Memory::VirtualRead(DWORD64 Address, void* Buffer, size_t Size) {
        DWORD bytesRead = 0;
        DWORD offset = 0;
        struct result resultdata;
        while (Size > 0) {
            // Read 4 bytes at a time or less if Size is less than 4 bytes
            DWORD chunkSize = (Size >= 0x04) ? 0x04 : Size;
            resultdata = ReadMemoryPrimitive(chunkSize, Address + offset);
            // Check if the read operation was successful
            if (!resultdata.resultstatus) {
                return false;  // Return false if the read operation fails
            }
            else {
                DWORD chunk = resultdata.resultvalue;
                // Copy the 4-byte chunk into the Buffer
                memcpy((BYTE*)Buffer + offset, &chunk, chunkSize);

                offset += chunkSize;
                Size -= chunkSize;
            }
        }
        return true;
}