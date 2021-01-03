#include <iostream>
#include <windows.h>
#include "debug.h"
#include "injector.h"

#define PROCESS_NAME L"notepad.exe"
#define DLL_NAME L"HelloWorld.dll"

#if !DEBUG
#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")
#endif

int main()
{
	LOG("[ ] Starting DLL injection: ", PROCESS_NAME, " into ", DLL_NAME);
	if (InjectDLL(PROCESS_NAME, DLL_NAME))
		LOG("[+] ", DLL_NAME, " has been injected into ", PROCESS_NAME);
	else
		LOG("[!] ", PROCESS_NAME, " could not be injected into ", DLL_NAME);

#if DEBUG
	std::cin.get();
#endif
	return 0;
}