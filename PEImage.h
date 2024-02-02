#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdint>

struct DOSHeader {
	uint32_t e_magic;
	uint32_t e_cblp;
	uint32_t e_cp;
	uint32_t e_crlc;
	uint32_t e_cparhdr;
	uint32_t e_minalloc;
	uint32_t e_maxalloc;
	uint32_t e_ss;
	uint32_t e_sp;
	uint32_t e_csum;
	uint32_t e_ip;
	uint32_t e_cs;
	uint32_t e_lfarlc;
	uint32_t e_ovno;
	uint32_t e_res[4];
	uint32_t e_oemid;
	uint32_t e_oeminfo;
	uint32_t e_res2[10];
	uint64_t e_lfanew;
};

struct COFFHeader {
	uint16_t MachineType;
	uint16_t NumberOfSections;
	uint32_t TimeDateStamp;
	uint32_t PointerToSymbolTable;
	uint32_t NumberOfSymbols;
	uint16_t SizeOfOptionalHeader;
	uint16_t Characteristics;
};

struct PE32PLUSHeaderStandardFields {
	uint16_t Magic;
	uint8_t MajorLinkVersion;
	uint8_t MinorLInkVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint;
	uint32_t BaseOfCode;
};

struct PE32HeaderStandardFields : PE32PLUSHeaderStandardFields{
	uint32_t BaseOfData;
};

struct PE32PLUSHeaderWindowsSpecifix {
	uint64_t ImageBase;
	uint32_t ImageAlignment;
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
	uint32_t NumberOfRVAAndSizes;
};

struct PE32HeaderWindowsSpecifix {
	uint32_t ImageBase;
	uint32_t ImageAlignment;
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
};

struct ImageDataDirectory {
	uint32_t VirtualAddress;
	uint32_t Size;
};

struct PE32PlusOptionalHeader {
	PE32PLUSHeaderStandardFields std;
	PE32PLUSHeaderWindowsSpecifix win;
	ImageDataDirectory dir[];
};

struct PE32OptionalHeader {
	PE32HeaderStandardFields std;
	PE32HeaderWindowsSpecifix win;
	ImageDataDirectory dir[];
};

constexpr size_t DOSHeaderSize =						sizeof(DOSHeader);
constexpr size_t COFFHeaderSize =						sizeof(COFFHeader);
constexpr size_t PE32PLUSHeaderStandardFieldsSize =		sizeof(PE32PLUSHeaderStandardFields);
constexpr size_t PE32HeaderStandardFieldsSize =			sizeof(PE32HeaderStandardFields);
constexpr size_t PE32PLUSHeaderWindowsSpecifixSize =	sizeof(PE32PLUSHeaderWindowsSpecifix);
constexpr size_t PE32HeaderWindowsSpecifixSize =		sizeof(PE32HeaderWindowsSpecifix);
constexpr size_t ImageDataDirectorySize =				sizeof(ImageDataDirectory);

constexpr const char* GetMachineTypeFromValue(uint16_t type)
{
	switch (type)
	{
	case IMAGE_FILE_MACHINE_UNKNOWN: return "IMAGE_FILE_MACHINE_UNKNOW";
	case IMAGE_FILE_MACHINE_ALPHA: return "IMAGE_FILE_MACHINE_ALPHA";
	case IMAGE_FILE_MACHINE_ALPHA64: return "IMAGE_FILE_MACHINE_ALPHA64";
	case IMAGE_FILE_MACHINE_AM33: return "IMAGE_FILE_MACHINE_AM33";
	case IMAGE_FILE_MACHINE_AMD64: return "IMAGE_FILE_MACHINE_AMD64";
	case IMAGE_FILE_MACHINE_ARM: return "IMAGE_FILE_MACHINE_ARM";
	case IMAGE_FILE_MACHINE_ARM64: return "IMAGE_FILE_MACHINE_ARM64";
	case IMAGE_FILE_MACHINE_ARMNT: return "IMAGE_FILE_MACHINE_ARMNT";
	case IMAGE_FILE_MACHINE_EBC: return "IMAGE_FILE_MACHINE_EBC";
	case IMAGE_FILE_MACHINE_I386: return "IMAGE_FILE_MACHINE_I386";
	case IMAGE_FILE_MACHINE_IA64: return "IMAGE_FILE_MACHINE_IA64";
	case 0x6232: return "IMAGE_FILE_MACHINE_LOONGARCH32";
	case 0x6264: return "IMAGE_FILE_MACHINE_LOONGARCH64";
	case IMAGE_FILE_MACHINE_M32R: return "IMAGE_FILE_MACHINE_M32R";
	case IMAGE_FILE_MACHINE_MIPS16: return "IMAGE_FILE_MACHINE_MIPS16";
	case IMAGE_FILE_MACHINE_MIPSFPU: return "IMAGE_FILE_MACHINE_MIPSFPU";
	case IMAGE_FILE_MACHINE_MIPSFPU16: return "IMAGE_FILE_MACHINE_MIPSFPU16";
	case IMAGE_FILE_MACHINE_POWERPC: return "IMAGE_FILE_MACHINE_POWERPC";
	case IMAGE_FILE_MACHINE_POWERPCFP: return "IMAGE_FILE_MACHINE_POWERPCFP";
	case IMAGE_FILE_MACHINE_R4000: return "IMAGE_FILE_MACHINE_R4000";
	case 0x5032: return "IMAGE_FILE_MACHINE_RISCV32";
	case 0x5064: return "IMAGE_FILE_MACHINE_RISCV64";
	case 0x5128: return "IMAGE_FILE_MACHINE_RISCV128";
	case IMAGE_FILE_MACHINE_SH3: return "IMAGE_FILE_MACHINE_SH3";
	case IMAGE_FILE_MACHINE_SH3DSP: return "IMAGE_FILE_MACHINE_SH3DSP";
	case IMAGE_FILE_MACHINE_SH4: return "IMAGE_FILE_MACHINE_SH4";
	case IMAGE_FILE_MACHINE_SH5: return "IMAGE_FILE_MACHINE_SH5";
	case IMAGE_FILE_MACHINE_THUMB: return "IMAGE_FILE_MACHINE_THUMB";
	case IMAGE_FILE_MACHINE_WCEMIPSV2: return "IMAGE_FILE_MACHINE_WCEMIPSV2";
	default: return "IMAGE_FILE_MACHINE_UNKNOW";
	}
}