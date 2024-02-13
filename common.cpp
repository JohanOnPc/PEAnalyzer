#include "common.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <iostream>
#include <format>

void PrintBytes(std::byte* map, __int64 size, int width)
{
	int64_t i = 0;
	
	for (; i < size; i++) {
		std::cout << std::format("{:02x} ", (unsigned char)map[i]);

		if ((i + 1) % width == 0)
			std::cout << '\n';
	}
	
	std::cout << '\n';
}
