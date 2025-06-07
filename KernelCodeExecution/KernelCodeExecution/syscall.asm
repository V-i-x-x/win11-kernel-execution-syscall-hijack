.code

EXTERN syscallNumber: DWORD

HijackedSyscall PROC
	mov r10, rcx
	mov eax, syscallNumber ; syscall number for NtAllocateVirtualMemory
	syscall
	ret
HijackedSyscall ENDP

end