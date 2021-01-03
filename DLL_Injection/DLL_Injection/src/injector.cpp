#include <windows.h>
#include <TlHelp32.h>
#include "debug.h"
#include "injector.h"

#pragma comment(lib, "advapi32.lib")

BOOL GrantDebugPriv(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tokenPriv;
	LUID luid;

	LOG("[ ] Opening process token");
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		LOG("[!] OpenProcessToken error: ", GetLastError());
		return FALSE;
	}
	LOG("[+] Process token opened");

	LOG("[ ] Retrieving LUID");
	if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
	{
		LOG("[!] LookupPriviledgeValue error: ", GetLastError());
		return FALSE;
	}
	LOG("[+] LUID retrieved");

	tokenPriv.PrivilegeCount = 1;
	tokenPriv.Privileges[0].Luid = luid;
	tokenPriv.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : NULL;

	LOG("[ ] Adjusting token privileges");
	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tokenPriv,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES) NULL,
		(PDWORD) NULL))
	{
		LOG("[!] AdjustTokenPrivileges error: ", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		LOG("[!] AdjustTokenPrivileges error: ", GetLastError());
		return FALSE;
	}
	LOG("[+] Token privileges adjusted");

	return TRUE;
}

DWORD FindProcessByName(PCWSTR processName)
{
	DWORD dwProcessID;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 procEntry;
	procEntry.dwSize = sizeof(procEntry);

	do {
		if (!_wcsicmp(procEntry.szExeFile, processName))
		{
			CloseHandle(hSnapshot);
			dwProcessID = procEntry.th32ProcessID;
			return dwProcessID;
		}
	} while (Process32Next(hSnapshot, &procEntry));

	return NULL;
}

BOOL InjectDLL(PCWSTR processName, PCWSTR dllPath)
{
	TCHAR dllFullPath[MAX_PATH];

	LOG("[ ] Granting debug privileges");

	if (!GrantDebugPriv(NULL, SE_DEBUG_NAME, TRUE))
		LOG("[!] Failed to grant debug privileges");
	else
		LOG("[+] Debug privileges granted");

	LOG("[ ] Starting process search for ", processName);

	DWORD dwProcessID = FindProcessByName(processName);

	if (dwProcessID == NULL)
	{
		LOG("[!] ", processName, " not found");
		return FALSE;
	}

	LOG("[+] ", processName, " found. PID: ", dwProcessID);
	LOG("[ ] checking if ", dllPath, " exists");

	GetFullPathName(dllPath, MAX_PATH, dllFullPath, NULL);

	if (_waccess_s(dllFullPath, 0) != 0)
	{
		LOG("[!] ", dllPath, " does not exist");
		return FALSE;
	}
	
	LOG("[+] ", dllPath, " found at: ", dllFullPath);
	LOG("[ ] Opening the ", processName, " process");

	HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, dwProcessID);

	if (hProcess == NULL)
	{
		LOG("[!] Could not get handle to process. Error: ", GetLastError());
		return FALSE;
	}

	LOG("[+] Handle to process opened");
	LOG("[ ] Allocating memory in ", processName);

	//DWORD dwMemSize = (DWORD)wcslen(dllFullPath) + 1;
	DWORD dwMemSize = (DWORD)MAX_PATH;

	LPVOID lpRemoteMemory = VirtualAllocEx(
		hProcess,
		NULL,
		dwMemSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);

	if (lpRemoteMemory == NULL)
	{
		LOG("[!] Failed to allocate memory with VirtualAllocEx. Error: ", GetLastError());
		return FALSE;
	}

	LOG("[+] Memory within the process has been allocated");

	LOG("[ ] Copying DLL path into the target process newly allocate memory");

	if (!WriteProcessMemory(
		hProcess,
		lpRemoteMemory,
		(LPCVOID)dllFullPath,
		dwMemSize,
		NULL))
	{
		LOG("[!] Failed to copy DLL path into allocated memory. Error: ", GetLastError());
		return FALSE;
	}

	LOG("[+] DLL path has been written into the allocated memory");
	LOG("[ ] Getting handle to kernel32.dll");

	HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
	if (hKernel32 == NULL)
	{
		LOG("[!] Failed to get handle to kernel32.dll. Error: ", GetLastError());
		return FALSE;
	}

	LOG("[+] Handle to kernel32.dll received");
	LOG("[ ] Retrieving the address of LoadLibraryW");

	LPVOID lpLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryW");
	if (lpLoadLibrary == NULL)
	{
		LOG("[!] Failed to get the address of LoadLibraryW. Error: ", GetLastError());
		return FALSE;
	}

	LOG("[+] Address of LoadLibraryW retrieved: ", lpLoadLibrary);
	LOG("[ ] Creating remote thread");

	HANDLE hRemoteThread = CreateRemoteThread(
		hProcess,
		NULL,
		NULL,
		(LPTHREAD_START_ROUTINE)lpLoadLibrary,
		lpRemoteMemory,
		NULL,
		NULL);

	if (hRemoteThread == NULL)
	{
		LOG("[!] Failed to start remote thread. Error: ", GetLastError());
		return FALSE;
	}

	LOG("[+] Remote thread started");

	WaitForSingleObject(hRemoteThread, INFINITE);

	VirtualFreeEx(hProcess, (LPVOID)lpRemoteMemory, 0, MEM_RELEASE);
	CloseHandle(hProcess);
	
	return TRUE;
}