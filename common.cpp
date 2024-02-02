#include "common.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <iostream>
#include <format>

void PrintBytes(std::byte* map, __int64 size, int width)
{
	__int64 i = 0;
	__try
	{
		for (; i < size; i++) {
			std::cout << std::format("{:02x} ", (unsigned char)map[i]);

			if ((i + 1) % width == 0)
				std::cout << '\n';
		}
	}
	__except (GetExceptionCode() == EXCEPTION_IN_PAGE_ERROR ?
		EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
		std::cout << "Got a page acces violation error for address: " << (std::byte*)(map + i) << '\n';
	}
}
