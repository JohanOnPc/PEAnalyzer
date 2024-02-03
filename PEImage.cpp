#include "PEImage.h"

#include <iostream>
#include <format>
#include <chrono>
#include <string>

#include "common.h"

bool CheckAndPrintDosHeader(std::byte* map, uint32_t& ImageHeader)
{
	DOSHeader* header = reinterpret_cast<DOSHeader*>(map);
	std::cout << "[*] DOS Header\n";
	std::cout << "    Magic: " << header->e_magic << '\n';
	std::cout << "    PE Address: " << std::format("{:08x}\n\n", header->e_lfanew);

	if (header->e_magic != 0x5A4D)
		return false;

	ImageHeader = header->e_lfanew;
	return true;
}

bool CheckAndPrintIfValidPE(NTImageHeader* header)
{
	std::cout << "[*] NT Header\n";
	std::cout << std::format("  Signature: {:08x}\n\n", header->Signature);
	if (0x00004550 != header->Signature)
		return false;

	PrintCOFFStructure(&header->COFF);

	return true;
}

void PrintCOFFStructure(COFFHeader* header)
{
	std::cout << "  [*] COFF File Header\n";
	std::cout << std::format("    Machine: {}\n", GetMachineTypeFromValue(header->MachineType));
	std::cout << std::format("    Number of Sections: {}\n", header->NumberOfSections);
	std::cout << std::format("    Timestamp: {}\n", std::chrono::sys_seconds{ std::chrono::seconds{ header->TimeDateStamp } });
	std::cout << std::format("    Symbol table address: {:08x}\n", header->PointerToSymbolTable);
	std::cout << std::format("    Number of Symbols: {}\n", header->NumberOfSymbols);
	std::cout << std::format("    Optional header size: {}\n", header->SizeOfOptionalHeader);
	std::cout << std::format("    Characteristics: {:016b}\n", header->Characteristics);

	for (int i = 1; i < (1 << 16); i <<= 1)
	{
		std::string characteristic = GetCharacteristicFromValue(header->Characteristics & i);
		if (!characteristic.empty())
			std::cout << std::format("      {}\n", characteristic);
	}
}
