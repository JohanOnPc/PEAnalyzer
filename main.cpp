#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <iostream>
#include <winnt.h>

#include "common.h"
#include "PEImage.h"

int main(int argc, char **argv)
{
	std::ios_base::sync_with_stdio(false);
	if (argc == 1)
	{
		std::cout << "Please specify a file to analyze!\n";
		return -1;
	}

	HANDLE file = CreateFileA(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (file == INVALID_HANDLE_VALUE)
	{
		std::cout << "CreateFile failed with error: " << GetLastError() << "\n";
		return -2;
	}

	HANDLE fileMapping = CreateFileMappingA(file, nullptr, PAGE_READONLY, 0, 0, nullptr);

	if (fileMapping == NULL)
	{
		std::cout << "CreateFileMapping failed with error: " << GetLastError() << "\n";
		return -3;
	}

	void* map = MapViewOfFile(fileMapping, FILE_MAP_READ, 0, 0, 0);

	if (map == nullptr)
	{
		std::cout << "MapViewOfFile failed with error: " << GetLastError() << "\n";
		return -4;
	}

	LARGE_INTEGER mapSize{};
	if (GetFileSizeEx(file, &mapSize) == false)
	{
		std::cout << "GetFileSizeEx failed with error: " << GetLastError() << '\n';
		return -5;
	}

	PEImage image(map);

	image.InitializeImage();
	image.PrintDosHeader();
	image.PrintCoffHeader();
	image.PrintImageNTHeaders();
	image.PrintDataDirectories();
	image.PrintSectionTables();
	image.PrintExportDirectoryTable();
	image.PrintImportDirectoryTable();

	UnmapViewOfFile(map);
	CloseHandle(fileMapping);
	CloseHandle(file);

	return 0;
}