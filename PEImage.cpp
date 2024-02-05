#include "PEImage.h"

#include <iostream>
#include <format>
#include <chrono>
#include <string>

#include "common.h"

bool CheckAndPrintDosHeader(std::byte* map, uint32_t& ImageHeader)
{
	ImageDosHeader* header = reinterpret_cast<ImageDosHeader*>(map);
	std::cout << "[*] DOS Header\n";
	std::cout << "    Magic: " << header->e_magic << '\n';
	std::cout << "    PE Address: " << std::format("0x{:08x}\n\n", header->e_lfanew);

	if (header->e_magic != 0x5A4D)
		return false;

	ImageHeader = header->e_lfanew;
	return true;
}

bool CheckAndPrintIfValidPE(ImageNTHeaders32* ImageHeader)
{
	std::cout << "[*] NT Header\n";
	std::cout << std::format("  Signature: 0x{:08x}\n\n", ImageHeader->Signature);
	if (0x00004550 != ImageHeader->Signature)
		return false;

	PrintCOFFStructure(&ImageHeader->FileHeader);
	PrintOptionalHeader(&ImageHeader->OptionalHeader);
	PrintSectionTable(reinterpret_cast<ImageSectionHeader*>((std::byte*)&ImageHeader->OptionalHeader + ImageHeader->FileHeader.SizeOfOptionalHeader), ImageHeader->FileHeader.NumberOfSections);

	return true;
}

void PrintCOFFStructure(ImageFileHeader* FileHeader)
{
	std::cout << "  [*] COFF File Header\n";
	std::cout << std::format("\tMachine: {}\n", GetMachineTypeFromValue(FileHeader->MachineType));
	std::cout << std::format("\tNumber of Sections: {}\n", FileHeader->NumberOfSections);
	std::cout << std::format("\tTimestamp: {}\n", std::chrono::sys_seconds{ std::chrono::seconds{ FileHeader->TimeDateStamp } });
	std::cout << std::format("\tSymbol table address: 0x{:08x}\n", FileHeader->PointerToSymbolTable);
	std::cout << std::format("\tNumber of Symbols: {}\n", FileHeader->NumberOfSymbols);
	std::cout << std::format("\tOptional header size: {}\n", FileHeader->SizeOfOptionalHeader);
	std::cout << std::format("\tCharacteristics: 0b{:016b}\n", FileHeader->Characteristics);

	for (int i = 1; i < (1 << 16); i <<= 1)
	{
		std::string characteristic = GetCharacteristicFromValue(FileHeader->Characteristics & i);
		if (!characteristic.empty())
			std::cout << std::format("\t\t{}\n", characteristic);
	}

	std::cout << '\n';
}

void PrintOptionalHeader(ImageOptionalHeader32* OptionalHeader)
{
	std::cout << "  [*] Optional Header\n";
	std::cout << std::format("\tMagic: 0x{:04x}", OptionalHeader->Magic);
	switch (OptionalHeader->Magic)
	{
	case PE32Magic: std::cout << " { PE32 }\n"; break;
	case PE32PlusMagic: std::cout << " { PE32+ }\n"; break;
	case ROMMagic: std::cout << "{ ROM }\n"; break;
	}

	uint16_t magic = OptionalHeader->Magic;

	std::cout << std::format("\tMajorLinkVersion: {}\n", OptionalHeader->MajorLinkVersion);
	std::cout << std::format("\tMinorLinkVersion: {}\n", OptionalHeader->MinorLInkVersion);
	std::cout << std::format("\tSizeOfCode: {}\n", OptionalHeader->SizeOfCode);
	std::cout << std::format("\tSizeOfInitializedData: {}\n", OptionalHeader->SizeOfInitializedData);
	std::cout << std::format("\tAddressOfEntryPoint: 0x{:08x}\n", OptionalHeader->AddressOfEntryPoint);
	std::cout << std::format("\tBaseOfCode: 0x{:08x}\n", OptionalHeader->BaseOfCode);

	if (magic == PE32Magic)
		ProcessAsPE32(OptionalHeader);
	else if (magic == PE32PlusMagic)
		ProcessAsPE32PLUS(reinterpret_cast<ImageOptionalHeader64*>(OptionalHeader));
}

void ProcessAsPE32(ImageOptionalHeader32* OptionalHeader)
{
	std::cout << std::format("\tBaseOfData: 0x{:08x}\n", OptionalHeader->BaseOfCode);
	std::cout << std::format("\tImageBase: 0x{:08x}\n", OptionalHeader->ImageBase);
	std::cout << std::format("\tSectionAlignment: {}\n", OptionalHeader->SectionAlignment);
	std::cout << std::format("\tFileAlignment: {}\n", OptionalHeader->FileAlignment);
	std::cout << std::format("\tMajorOperatingSystemVersion: {}\n", OptionalHeader->MajorOperatingSystemVersion);
	std::cout << std::format("\tMinorOperatingSystemVersion: {}\n", OptionalHeader->MinorOperatingSystemVersion);
	std::cout << std::format("\tMajorImageVersion: {}\n", OptionalHeader->MajorImageVersion);
	std::cout << std::format("\tMinorImageVersion: {}\n", OptionalHeader->MinorImageVersion);
	std::cout << std::format("\tMajorSubsystemVersion: {}\n", OptionalHeader->MajorSubsystemVersion);
	std::cout << std::format("\tMinorSubsystemVersion: {}\n", OptionalHeader->MinorSubsystemVersion);
	std::cout << std::format("\tWin32VersionValue: {}\n", OptionalHeader->Win32VersionValue);
	std::cout << std::format("\tSizeOfImage: {}\n", OptionalHeader->SizeOfImage);
	std::cout << std::format("\tSizeOfHeaders: {}\n", OptionalHeader->SizeOfHeaders);
	std::cout << std::format("\tCheckSum: 0x{:08x}\n", OptionalHeader->CheckSum);
	std::cout << std::format("\tSubsystem: {}\n", OptionalHeader->DLLCharacteristics);
	std::cout << std::format("\tSizeOfStackReserve: {}\n", OptionalHeader->SizeOfStackReserve);
	std::cout << std::format("\tSizeOfStackCommit: {}\n", OptionalHeader->SizeOfStackCommit);
	std::cout << std::format("\tSizeOfHeapReserve: {}\n", OptionalHeader->SizeOfHeapReserve);
	std::cout << std::format("\tSizeOfHeapCommit: {}\n", OptionalHeader->SizeOfHeapCommit);
	std::cout << std::format("\tLoaderFlags: {}\n", OptionalHeader->LoaderFlags);
	std::cout << std::format("\tNumberOfRvaAndSize: {}\n\n", OptionalHeader->NumberOfRvaAndSizes);

	PrintDataDirectories(OptionalHeader->DataDirectory, OptionalHeader->NumberOfRvaAndSizes);
}

void ProcessAsPE32PLUS(ImageOptionalHeader64* OptionalHeader)
{
	std::cout << std::format("\tImageBase: 0x{:016x}\n", OptionalHeader->ImageBase);
	std::cout << std::format("\tSectionAlignment: {}\n", OptionalHeader->SectionAlignment);
	std::cout << std::format("\tFileAlignment: {}\n", OptionalHeader->FileAlignment);
	std::cout << std::format("\tMajorOperatingSystemVersion: {}\n", OptionalHeader->MajorOperatingSystemVersion);
	std::cout << std::format("\tMinorOperatingSystemVersion: {}\n", OptionalHeader->MinorOperatingSystemVersion);
	std::cout << std::format("\tMajorImageVersion: {}\n", OptionalHeader->MajorImageVersion);
	std::cout << std::format("\tMinorImageVersion: {}\n", OptionalHeader->MinorImageVersion);
	std::cout << std::format("\tMajorSubsystemVersion: {}\n", OptionalHeader->MajorSubsystemVersion);
	std::cout << std::format("\tMinorSubsystemVersion: {}\n", OptionalHeader->MinorSubsystemVersion);
	std::cout << std::format("\tWin32VersionValue: {}\n", OptionalHeader->Win32VersionValue);
	std::cout << std::format("\tSizeOfImage: {}\n", OptionalHeader->SizeOfImage);
	std::cout << std::format("\tSizeOfHeaders: {}\n", OptionalHeader->SizeOfHeaders);
	std::cout << std::format("\tCheckSum: 0x{:08x}\n", OptionalHeader->CheckSum);
	std::cout << std::format("\tSubsystem: {}\n", OptionalHeader->DLLCharacteristics);
	std::cout << std::format("\tSizeOfStackReserve: {}\n", OptionalHeader->SizeOfStackReserve);
	std::cout << std::format("\tSizeOfStackCommit: {}\n", OptionalHeader->SizeOfStackCommit);
	std::cout << std::format("\tSizeOfHeapReserve: {}\n", OptionalHeader->SizeOfHeapReserve);
	std::cout << std::format("\tSizeOfHeapCommit: {}\n", OptionalHeader->SizeOfHeapCommit);
	std::cout << std::format("\tLoaderFlags: {}\n", OptionalHeader->LoaderFlags);
	std::cout << std::format("\tNumberOfRvaAndSize: {}\n\n", OptionalHeader->NumberOfRvaAndSizes);

	PrintDataDirectories(OptionalHeader->DataDirectory, OptionalHeader->NumberOfRvaAndSizes);
}

void PrintDataDirectories(ImageDataDirectory* DataDirectory, uint32_t count)
{
	for (uint32_t i = 0; i < count; i++)
	{
		std::cout << std::format("\t{}\n", GetDataDirectoryNameFromValue(i));
		std::cout << std::format("\t\tVirtualAddress: 0x{:08x}\n", DataDirectory[i].VirtualAddress);
		std::cout << std::format("\t\tSize: {}\n", DataDirectory[i].Size);
	}
}

void PrintSectionTable(ImageSectionHeader* SectionHeader, uint16_t count)
{
	std::cout << "\n  [*] Image Section Headers\n";
	for (uint16_t i = 0; i < count; i++)
	{
		std::cout << std::format("\tName: {:.8s}\n", SectionHeader[i].Name);
		std::cout << std::format("\t\tVirtualSize: {:}\n", SectionHeader[i].VirtualSize);
		std::cout << std::format("\t\tVirtalAddress: 0x{:08x}\n", SectionHeader[i].VirtualAddress);
		std::cout << std::format("\t\tSizeOfRawData: {}\n", SectionHeader[i].SizeOfRawData);
		std::cout << std::format("\t\tPointerToRawData: 0x{:08x}\n", SectionHeader[i].PointerToRawData);
		std::cout << std::format("\t\tPointerToRelocations: 0x{:08x}\n", SectionHeader[i].PointerToRelocations);
		std::cout << std::format("\t\tPointerToLineNumbers: 0x{:08x}\n", SectionHeader[i].PointerToLineNumbers);
		std::cout << std::format("\t\tNumberOfRelocations: {}\n", SectionHeader[i].NumberOfRelocations);
		std::cout << std::format("\t\tNumberOfLineNumbers: {}\n", SectionHeader[i].NumberOfLineNumbers);
		std::cout << std::format("\t\tCharacteristics: 0b{:032b}\n", SectionHeader[i].Characteristics);
	}
}
