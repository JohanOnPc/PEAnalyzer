#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdint>
#include <cstddef>

#include "PEFormat.h"

class PEImage {
public:
	PEImage(void *const base);

	void InitializeImage();
	void PrintDosHeader() const;



private:
	void *const ImageBase;

	ImageDosHeader *const DosHeader;
	union
	{
		ImageNTHeaders32* NTHeaders32 = nullptr;
		ImageNTHeaders64* NTHeaders64;
	};

	uint16_t ImageType = 0;
};

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

constexpr const char* GetCharacteristicFromValue(uint16_t value)
{
	switch (value)
	{
	case IMAGE_FILE_RELOCS_STRIPPED: return "IMAGE_FILE_RELOCS_STRIPPED";
	case IMAGE_FILE_EXECUTABLE_IMAGE: return "IMAGE_FILE_EXECUTABLE_IMAGE";
	case IMAGE_FILE_LINE_NUMS_STRIPPED: return "IMAGE_FILE_LINE_NUMS_STRIPPED";
	case IMAGE_FILE_LOCAL_SYMS_STRIPPED: return "IMAGE_FILE_LOCAL_SYMS_STRIPPED";
	case 0x0010: return "IMAGE_FILE_AGGRESSIVE_WS_TRIM";
	case IMAGE_FILE_LARGE_ADDRESS_AWARE: return "IMAGE_FILE_LARGE_ADDRESS_AWARE";
	case IMAGE_FILE_BYTES_REVERSED_LO: return "IMAGE_FILE_BYTES_REVERSED_LO";
	case IMAGE_FILE_32BIT_MACHINE: return "IMAGE_FILE_32BIT_MACHINE";
	case IMAGE_FILE_DEBUG_STRIPPED: return "IMAGE_FILE_DEBUG_STRIPPED";
	case IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP: return "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP";
	case IMAGE_FILE_NET_RUN_FROM_SWAP: return "IMAGE_FILE_NET_RUN_FROM_SWAP";
	case IMAGE_FILE_SYSTEM: return "IMAGE_FILE_SYSTEM";
	case IMAGE_FILE_DLL: return "IMAGE_FILE_DLL";
	case IMAGE_FILE_UP_SYSTEM_ONLY: return "IMAGE_FILE_UP_SYSTEM_ONLY";
	case IMAGE_FILE_BYTES_REVERSED_HI: return "IMAGE_FILE_BYTES_REVERSED_HI";
	default: return "";
	}
}

constexpr const char* GetSubsystemFromValue(uint16_t value)
{
	switch (value)
	{
	case IMAGE_SUBSYSTEM_UNKNOWN: return "IMAGE_SUBSYSTEM_UNKNOWN";
	case IMAGE_SUBSYSTEM_NATIVE: return "IMAGE_SUBSYSTEM_NATIVE";
	case IMAGE_SUBSYSTEM_WINDOWS_GUI: return "IMAGE_SUBSYSTEM_WINDOWS_GUI";
	case IMAGE_SUBSYSTEM_WINDOWS_CUI: return "IMAGE_SUBSYSTEM_WINDOWS_CUI";
	case IMAGE_SUBSYSTEM_OS2_CUI: return "IMAGE_SUBSYSTEM_OS2_CUI";
	case IMAGE_SUBSYSTEM_POSIX_CUI: return "IMAGE_SUBSYSTEM_POSIX_CUI";
	case IMAGE_SUBSYSTEM_NATIVE_WINDOWS: return "IMAGE_SUBSYSTEM_NATIVE_WINDOWS";
	case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI: return "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI";
	case IMAGE_SUBSYSTEM_EFI_APPLICATION: return "IMAGE_SUBSYSTEM_EFI_APPLICATION";
	case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: return "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER";
	case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER : return "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER";
	case IMAGE_SUBSYSTEM_EFI_ROM: return "IMAGE_SUBSYSTEM_EFI_ROM";
	case IMAGE_SUBSYSTEM_XBOX: return "IMAGE_SUBSYSTEM_XBOX";
	case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: return "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION";
	default: return "";
	}
}

constexpr const char* GetDllCharacteristicsFromValue(uint16_t value)
{
	switch (value)
	{
	case IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: return "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA";
	case IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: return "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE";
	case IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: return "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY";
	case IMAGE_DLLCHARACTERISTICS_NX_COMPAT: return "IMAGE_DLLCHARACTERISTICS_NX_COMPAT";
	case IMAGE_DLLCHARACTERISTICS_NO_ISOLATION: return "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION";
	case IMAGE_DLLCHARACTERISTICS_NO_SEH: return "IMAGE_DLLCHARACTERISTICS_NO_SEH";
	case IMAGE_DLLCHARACTERISTICS_NO_BIND: return "IMAGE_DLLCHARACTERISTICS_NO_BIND";
	case IMAGE_DLLCHARACTERISTICS_APPCONTAINER: return "IMAGE_DLLCHARACTERISTICS_APPCONTAINER";
	case IMAGE_DLLCHARACTERISTICS_WDM_DRIVER: return "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER";
	case IMAGE_DLLCHARACTERISTICS_GUARD_CF: return "IMAGE_DLLCHARACTERISTICS_GUARD_CF";
	case IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE: return "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE";
	default: return "";
	}
}

constexpr const char* GetSectionCharacteristicsFromValue(uint32_t value)
{
	switch (value)
	{
	case IMAGE_SCN_TYPE_NO_PAD: return "IMAGE_SCN_TYPE_NO_PAD";
	case IMAGE_SCN_CNT_CODE: return "IMAGE_SCN_CNT_CODE";
	case IMAGE_SCN_CNT_INITIALIZED_DATA: return "IMAGE_SCN_CNT_INITIALIZED_DATA";
	case IMAGE_SCN_CNT_UNINITIALIZED_DATA: return "IMAGE_SCN_CNT_UNINITIALIZED_DATA";
	case IMAGE_SCN_LNK_INFO: return "IMAGE_SCN_LNK_INFO";
	case IMAGE_SCN_LNK_REMOVE: return "IMAGE_SCN_LNK_REMOVE";
	case IMAGE_SCN_LNK_COMDAT: return "IMAGE_SCN_LNK_COMDAT";
	case IMAGE_SCN_GPREL: return "IMAGE_SCN_GPREL";
	case IMAGE_SCN_ALIGN_1BYTES: return "IMAGE_SCN_ALIGN_1BYTES";
	case IMAGE_SCN_ALIGN_2BYTES: return "IMAGE_SCN_ALIGN_2BYTES";
	case IMAGE_SCN_ALIGN_4BYTES: return "IMAGE_SCN_ALIGN_4BYTES";
	case IMAGE_SCN_ALIGN_8BYTES: return "IMAGE_SCN_ALIGN_8BYTES";
	case IMAGE_SCN_ALIGN_16BYTES: return "IMAGE_SCN_ALIGN_16BYTES";
	case IMAGE_SCN_ALIGN_32BYTES: return "IMAGE_SCN_ALIGN_32BYTES";
	case IMAGE_SCN_ALIGN_64BYTES: return "IMAGE_SCN_ALIGN_64BYTES";
	case IMAGE_SCN_ALIGN_128BYTES: return "IMAGE_SCN_ALIGN_128BYTES";
	case IMAGE_SCN_ALIGN_256BYTES: return "IMAGE_SCN_ALIGN_256BYTES";
	case IMAGE_SCN_ALIGN_512BYTES: return "IMAGE_SCN_ALIGN_512BYTES";
	case IMAGE_SCN_ALIGN_1024BYTES: return "IMAGE_SCN_ALIGN_1024BYTES";
	case IMAGE_SCN_ALIGN_2048BYTES: return "IMAGE_SCN_ALIGN_2048BYTES";
	case IMAGE_SCN_ALIGN_4096BYTES: return "IMAGE_SCN_ALIGN_4096BYTES";
	case IMAGE_SCN_ALIGN_8192BYTES: return "IMAGE_SCN_ALIGN_8192BYTES";
	case IMAGE_SCN_LNK_NRELOC_OVFL: return "IMAGE_SCN_LNK_NRELOC_OVFL";
	case IMAGE_SCN_MEM_DISCARDABLE: return "IMAGE_SCN_MEM_DISCARDABLE";
	case IMAGE_SCN_MEM_NOT_CACHED: return "IMAGE_SCN_MEM_NOT_CACHED";
	case IMAGE_SCN_MEM_NOT_PAGED: return "IMAGE_SCN_MEM_NOT_PAGED";
	case IMAGE_SCN_MEM_SHARED: return "IMAGE_SCN_MEM_SHARED";
	case IMAGE_SCN_MEM_EXECUTE: return "IMAGE_SCN_MEM_EXECUTE";
	case IMAGE_SCN_MEM_READ: return "IMAGE_SCN_MEM_READ";
	case IMAGE_SCN_MEM_WRITE: return "IMAGE_SCN_MEM_WRITE";
	default: return "";
	}
}

constexpr const char* GetDataDirectoryNameFromValue(uint8_t value)
{
	switch (value)
	{
	case IMAGE_DIRECTORY_ENTRY_EXPORT: return "IMAGE_DIRECTORY_ENTRY_EXPORT";
	case IMAGE_DIRECTORY_ENTRY_IMPORT: return "IMAGE_DIRECTORY_ENTRY_IMPORT";
	case IMAGE_DIRECTORY_ENTRY_RESOURCE: return "IMAGE_DIRECTORY_ENTRY_RESOURCE";
	case IMAGE_DIRECTORY_ENTRY_EXCEPTION: return "IMAGE_DIRECTORY_ENTRY_EXCEPTION";
	case IMAGE_DIRECTORY_ENTRY_SECURITY: return "IMAGE_DIRECTORY_ENTRY_SECURITY";
	case IMAGE_DIRECTORY_ENTRY_BASERELOC: return "IMAGE_DIRECTORY_ENTRY_BASERELOC";
	case IMAGE_DIRECTORY_ENTRY_DEBUG: return "IMAGE_DIRECTORY_ENTRY_DEBUG";
	case IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: return "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE";
	case IMAGE_DIRECTORY_ENTRY_GLOBALPTR: return "IMAGE_DIRECTORY_ENTRY_GLOBALPTR";
	case IMAGE_DIRECTORY_ENTRY_TLS: return "IMAGE_DIRECTORY_ENTRY_TLS";
	case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: return "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG";
	case IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: return "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT";
	case IMAGE_DIRECTORY_ENTRY_IAT: return "IMAGE_DIRECTORY_ENTRY_IAT";
	case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: return "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT";
	case IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: return "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR";
	case 15: return "RESERVED";
	default: return "ERROR";
	}
}

bool CheckAndPrintDosHeader(std::byte* map, uint32_t& ImageHeader);
bool CheckAndPrintIfValidPE(ImageNTHeaders32* ImageHeader);
void PrintCOFFStructure(ImageFileHeader* FileHeader);
void PrintOptionalHeader(ImageOptionalHeader32* OptionalHeader);

void ProcessAsPE32(ImageOptionalHeader32* OptionalHeader);
void ProcessAsPE32PLUS(ImageOptionalHeader64* OptionalHeader);
void PrintDataDirectories(ImageDataDirectory* DataDirectory, uint32_t count);

void PrintSectionTable(ImageSectionHeader* SectionHeader, uint16_t count);
void PrintImportDirectoryTable(ImageImportDescriptor* ImportDescriptor);