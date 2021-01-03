#pragma once

#include <windows.h>

BOOL  GrantDebugPriv(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
DWORD FindProcessByName(PCWSTR processName);
BOOL InjectDLL(PCWSTR processName, PCWSTR dllPath);