#pragma once

#include <windows.h>
#include <iostream>

#define DEBUG 0

template<typename ...Args>
VOID LOG(Args && ...args)
{
#if DEBUG == 1
	(std::wcout << ... << args);
	std::wcout << "\n";
#endif
}