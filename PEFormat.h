#pragma once

#include <cstdint>

struct ImageDosHeader {
	uint16_t e_magic;
	uint16_t e_cblp;
	uint16_t e_cp;
	uint16_t e_crlc;
	uint16_t e_cparhdr;
	uint16_t e_minalloc;
	uint16_t e_maxalloc;
	uint16_t e_ss;
	uint16_t e_sp;
	uint16_t e_csum;
	uint16_t e_ip;
	uint16_t e_cs;
	uint16_t e_lfarlc;
	uint16_t e_ovno;
	uint16_t e_res[4];
	uint16_t e_oemid;
	uint16_t e_oeminfo;
	uint16_t e_res2[10];
	uint32_t e_lfanew;
};

struct ImageFileHeader {
	uint16_t MachineType;
	uint16_t NumberOfSections;
	uint32_t TimeDateStamp;
	uint32_t PointerToSymbolTable;
	uint32_t NumberOfSymbols;
	uint16_t SizeOfOptionalHeader;
	uint16_t Characteristics;
};

struct ImageDataDirectory {
	uint32_t VirtualAddress;
	uint32_t Size;
};

struct ImageOptionalHeader64 {
	uint16_t Magic;
	uint8_t MajorLinkVersion;
	uint8_t MinorLInkVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint;
	uint32_t BaseOfCode;
	uint64_t ImageBase;
	uint32_t SectionAlignment;
	uint32_t FileAlignment;
	uint16_t MajorOperatingSystemVersion;
	uint16_t MinorOperatingSystemVersion;
	uint16_t MajorImageVersion;
	uint16_t MinorImageVersion;
	uint16_t MajorSubsystemVersion;
	uint16_t MinorSubsystemVersion;
	uint32_t Win32VersionValue;
	uint32_t SizeOfImage;
	uint32_t SizeOfHeaders;
	uint32_t CheckSum;
	uint16_t Subsystem;
	uint16_t DLLCharacteristics;
	uint64_t SizeOfStackReserve;
	uint64_t SizeOfStackCommit;
	uint64_t SizeOfHeapReserve;
	uint64_t SizeOfHeapCommit;
	uint32_t LoaderFlags;
	uint32_t NumberOfRvaAndSizes;
	ImageDataDirectory DataDirectory[16];
};

struct ImageOptionalHeader32 {
	uint16_t Magic;
	uint8_t MajorLinkVersion;
	uint8_t MinorLInkVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint;
	uint32_t BaseOfCode;
	uint32_t BaseOfData;
	uint32_t ImageBase;
	uint32_t SectionAlignment;
	uint32_t FileAlignment;
	uint16_t MajorOperatingSystemVersion;
	uint16_t MinorOperatingSystemVersion;
	uint16_t MajorImageVersion;
	uint16_t MinorImageVersion;
	uint16_t MajorSubsystemVersion;
	uint16_t MinorSubsystemVersion;
	uint32_t Win32VersionValue;
	uint32_t SizeOfImage;
	uint32_t SizeOfHeaders;
	uint32_t CheckSum;
	uint16_t Subsystem;
	uint16_t DLLCharacteristics;
	uint32_t SizeOfStackReserve;
	uint32_t SizeOfStackCommit;
	uint32_t SizeOfHeapReserve;
	uint32_t SizeOfHeapCommit;
	uint32_t LoaderFlags;
	uint32_t NumberOfRvaAndSizes;
	ImageDataDirectory DataDirectory[16];
};

struct ImageNTHeaders64 {
	uint32_t Signature;
	ImageFileHeader FileHeader;
	ImageOptionalHeader64 OptionalHeader;
};

struct ImageNTHeaders32 {
	uint32_t Signature;
	ImageFileHeader FileHeader;
	ImageOptionalHeader32 OptionalHeader;
};

struct ImageSectionHeader {
	char Name[8];
	uint32_t VirtualSize;
	uint32_t VirtualAddress;
	uint32_t SizeOfRawData;
	uint32_t PointerToRawData;
	uint32_t PointerToRelocations;
	uint32_t PointerToLineNumbers;
	uint16_t NumberOfRelocations;
	uint16_t NumberOfLineNumbers;
	uint32_t Characteristics;
};

struct ImageImportDescriptor {
	uint32_t ImportLookupTableRva;
	uint32_t Timestamp;
	uint32_t ForwarderChain;
	uint32_t NameRva;
	uint32_t ImportAddressTableRva;
};

constexpr size_t ImageDosHeaderSize = sizeof(ImageDosHeader);
constexpr size_t ImageFileHeaderSize = sizeof(ImageFileHeader);
constexpr size_t ImageOptionalHeader64Size = sizeof(ImageOptionalHeader64);
constexpr size_t ImageOptionalHeader32Size = sizeof(ImageOptionalHeader32);
constexpr size_t ImageDataDirectorySize = sizeof(ImageDataDirectory);
constexpr size_t ImageNTHeaders64Size = sizeof(ImageNTHeaders64);
constexpr size_t ImageNTHeaders32Size = sizeof(ImageNTHeaders32);
constexpr size_t ImageSectionHeaderSize = sizeof(ImageSectionHeader);
constexpr size_t ImageImportDescriptorSize = sizeof(ImageImportDescriptor);

constexpr uint16_t PE32Magic = 0x10B;
constexpr uint16_t ROMMagic = 0x107;
constexpr uint16_t PE32PlusMagic = 0x20B;