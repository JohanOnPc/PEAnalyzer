#include "PEImage.h"

#include <iostream>
#include <format>
#include <chrono>
#include <string>
#include <exception>

#include "common.h"

PEImage::PEImage(void *const base) : ImageBase(base), DosHeader(reinterpret_cast<ImageDosHeader *const>(base))
{
}

void PEImage::InitializeImage()
{
    if (DosHeader->e_magic != 0x5A4D)
        throw std::exception("Image does not contain the valid DOS magic: 'MZ'!");

    NTHeaders32 = reinterpret_cast<ImageNTHeaders32*>((std::byte*)ImageBase + DosHeader->e_lfanew);

    if (NTHeaders32->Signature != 0x00004550)
        throw std::exception("Image does not contain the valid PE signature 'PE\\0\\0'");

    ImageType = NTHeaders32->OptionalHeader.Magic;
    SectionHeaderCount = NTHeaders32->FileHeader.NumberOfSections;

    SectionHeader = reinterpret_cast<ImageSectionHeader*>((std::byte*)&NTHeaders32->OptionalHeader + NTHeaders32->FileHeader.SizeOfOptionalHeader);
    
    if (ImageType == PE32Magic)
    {
        DataDirectory = NTHeaders32->OptionalHeader.DataDirectory;
        DataDirectoriesCount = NTHeaders32->OptionalHeader.NumberOfRvaAndSizes;
    }
    else if (ImageType == PE32PlusMagic)
    {
        DataDirectory = NTHeaders64->OptionalHeader.DataDirectory;
        DataDirectoriesCount = NTHeaders64->OptionalHeader.NumberOfRvaAndSizes;
    }
}

void PEImage::PrintDosHeader() const
{
    std::cout << "[*] DOS Header\n";
    std::cout << std::format("\te_magic:    {:#02x} ({:c}{:c})\n", DosHeader->e_magic, DosHeader->e_magic & 0xFF, DosHeader->e_magic >> 8);
    std::cout << std::format("\te_cblp:	    {}\n", DosHeader->e_cblp);
    std::cout << std::format("\te_cp:	    {}\n", DosHeader->e_cp);
    std::cout << std::format("\te_crlc:     {}\n", DosHeader->e_crlc);
    std::cout << std::format("\te_cparhdr:  {}\n", DosHeader->e_cparhdr);
    std::cout << std::format("\te_minalloc: {}\n", DosHeader->e_minalloc);
    std::cout << std::format("\te_maxalloc: {}\n", DosHeader->e_maxalloc);
    std::cout << std::format("\te_ss:       {}\n", DosHeader->e_ss);
    std::cout << std::format("\te_sp:       {}\n", DosHeader->e_sp);
    std::cout << std::format("\te_csum:     {}\n", DosHeader->e_csum);
    std::cout << std::format("\te_ip:       {}\n", DosHeader->e_ip);
    std::cout << std::format("\te_cs:       {}\n", DosHeader->e_cs);
    std::cout << std::format("\te_lfarlc:   {}\n", DosHeader->e_lfarlc);
    std::cout << std::format("\te_ovno:     {}\n", DosHeader->e_ovno);
    std::cout << std::format("\te_oemid:    {}\n", DosHeader->e_oemid);
    std::cout << std::format("\te_oeminfo:  {}\n", DosHeader->e_oeminfo);
    std::cout << std::format("\te_lfanew:   {:#06x}\n", DosHeader->e_lfanew);

    std::cout << '\n';
}

void PEImage::PrintCoffHeader() const
{
    ImageFileHeader* FileHeader = &NTHeaders32->FileHeader;
    std::cout << "[*] COFF File Header\n";
    std::cout << std::format("\tMachine:                {}\n", GetMachineTypeFromValue(FileHeader->MachineType));
    std::cout << std::format("\tNumber of Sections:     {}\n", FileHeader->NumberOfSections);
    std::cout << std::format("\tTimestamp:              {}\n", std::chrono::sys_seconds{ std::chrono::seconds{ FileHeader->TimeDateStamp } });
    std::cout << std::format("\tSymbol table address:   {:#010x}\n", FileHeader->PointerToSymbolTable);
    std::cout << std::format("\tNumber of Symbols:      {}\n", FileHeader->NumberOfSymbols);
    std::cout << std::format("\tOptional header size:   {}\n", FileHeader->SizeOfOptionalHeader);
    std::cout << std::format("\tCharacteristics:        {:#018b}\n", FileHeader->Characteristics);

    for (int i = 1; i < (1 << 16); i <<= 1)
    {
        std::string characteristic = GetCharacteristicFromValue(FileHeader->Characteristics & i);
        if (!characteristic.empty())
            std::cout << std::format("\t\t{}\n", characteristic);
    }

    std::cout << '\n';
}

void PEImage::PrintImageNTHeaders() const
{
    switch (ImageType)
    {
    case PE32Magic: 
        PrintImageNTHeaders32();
        return;
    case PE32PlusMagic:
        PrintImageNTHeaders64();
        return;
    case ROMMagic:
        return;
    default:
        return;
    }
}

void PEImage::PrintImageNTHeaders64() const
{
    ImageOptionalHeader64* OptionalHeader = &NTHeaders64->OptionalHeader;

    std::cout << "[*] Optional Header\n";
    std::cout << std::format("\tMagic:                          {:#06x} ( {} )\n", ImageType, GetImageTypeFromValue(ImageType));
    std::cout << std::format("\tMajorLinkVersion:               {}\n", OptionalHeader->MajorLinkVersion);
    std::cout << std::format("\tMinorLinkVersion:               {}\n", OptionalHeader->MinorLInkVersion);
    std::cout << std::format("\tSizeOfCode:                     {}\n", OptionalHeader->SizeOfCode);
    std::cout << std::format("\tSizeOfInitializedData:          {}\n", OptionalHeader->SizeOfInitializedData);
    std::cout << std::format("\tAddressOfEntryPoint:            {:#010x}\n", OptionalHeader->AddressOfEntryPoint);
    std::cout << std::format("\tBaseOfCode:                     {:#010x}\n", OptionalHeader->BaseOfCode);

    std::cout << std::format("\tImageBase:                      {:#018x}\n", OptionalHeader->ImageBase);
    std::cout << std::format("\tSectionAlignment:               {}\n", OptionalHeader->SectionAlignment);
    std::cout << std::format("\tFileAlignment:                  {}\n", OptionalHeader->FileAlignment);
    std::cout << std::format("\tMajorOperatingSystemVersion:    {}\n", OptionalHeader->MajorOperatingSystemVersion);
    std::cout << std::format("\tMinorOperatingSystemVersion:    {}\n", OptionalHeader->MinorOperatingSystemVersion);
    std::cout << std::format("\tMajorImageVersion:              {}\n", OptionalHeader->MajorImageVersion);
    std::cout << std::format("\tMinorImageVersion:              {}\n", OptionalHeader->MinorImageVersion);
    std::cout << std::format("\tMajorSubsystemVersion:          {}\n", OptionalHeader->MajorSubsystemVersion);
    std::cout << std::format("\tMinorSubsystemVersion:          {}\n", OptionalHeader->MinorSubsystemVersion);
    std::cout << std::format("\tWin32VersionValue:              {}\n", OptionalHeader->Win32VersionValue);
    std::cout << std::format("\tSizeOfImage:                    {}\n", OptionalHeader->SizeOfImage);
    std::cout << std::format("\tSizeOfHeaders:                  {}\n", OptionalHeader->SizeOfHeaders);
    std::cout << std::format("\tCheckSum:                       {:#010x}\n", OptionalHeader->CheckSum);
    std::cout << std::format("\tSubsystem:                      {} ({})\n", OptionalHeader->Subsystem, GetSubsystemFromValue(OptionalHeader->Subsystem));
    std::cout << std::format("\tDllCharacteristics:             {:#18b}\n", OptionalHeader->DLLCharacteristics);

    for (uint32_t j = 1; j < (1 << 16); j <<= 1)
    {
        std::string characteristic = GetDllCharacteristicsFromValue(OptionalHeader->DLLCharacteristics & j);
        if (!characteristic.empty())
            std::cout << std::format("\t\t{}\n", characteristic);
    }

    std::cout << std::format("\tSizeOfStackReserve:             {}\n", OptionalHeader->SizeOfStackReserve);
    std::cout << std::format("\tSizeOfStackCommit:              {}\n", OptionalHeader->SizeOfStackCommit);
    std::cout << std::format("\tSizeOfHeapReserve:              {}\n", OptionalHeader->SizeOfHeapReserve);
    std::cout << std::format("\tSizeOfHeapCommit:               {}\n", OptionalHeader->SizeOfHeapCommit);
    std::cout << std::format("\tLoaderFlags:                    {}\n", OptionalHeader->LoaderFlags);
    std::cout << std::format("\tNumberOfRvaAndSize:             {}\n\n", OptionalHeader->NumberOfRvaAndSizes);
}

void PEImage::PrintImageNTHeaders32() const
{
    ImageOptionalHeader32* OptionalHeader = &NTHeaders32->OptionalHeader;

    std::cout << "[*] Optional Header\n";
    std::cout << std::format("\tMagic:                          {:#06x} ( {} )\n", ImageType, GetImageTypeFromValue(ImageType));
    std::cout << std::format("\tMajorLinkVersion:               {}\n", OptionalHeader->MajorLinkVersion);
    std::cout << std::format("\tMinorLinkVersion:               {}\n", OptionalHeader->MinorLInkVersion);
    std::cout << std::format("\tSizeOfCode:                     {}\n", OptionalHeader->SizeOfCode);
    std::cout << std::format("\tSizeOfInitializedData:          {}\n", OptionalHeader->SizeOfInitializedData);
    std::cout << std::format("\tAddressOfEntryPoint:            {:#010x}\n", OptionalHeader->AddressOfEntryPoint);
    std::cout << std::format("\tBaseOfCode:                     {:#010x}\n", OptionalHeader->BaseOfCode);

    std::cout << std::format("\tBaseOfData:                     {:#010x}\n", OptionalHeader->BaseOfCode);
    std::cout << std::format("\tImageBase:                      {:#010x}\n", OptionalHeader->ImageBase);
    std::cout << std::format("\tSectionAlignment:               {}\n", OptionalHeader->SectionAlignment);
    std::cout << std::format("\tFileAlignment:                  {}\n", OptionalHeader->FileAlignment);
    std::cout << std::format("\tMajorOperatingSystemVersion:    {}\n", OptionalHeader->MajorOperatingSystemVersion);
    std::cout << std::format("\tMinorOperatingSystemVersion:    {}\n", OptionalHeader->MinorOperatingSystemVersion);
    std::cout << std::format("\tMajorImageVersion:              {}\n", OptionalHeader->MajorImageVersion);
    std::cout << std::format("\tMinorImageVersion:              {}\n", OptionalHeader->MinorImageVersion);
    std::cout << std::format("\tMajorSubsystemVersion:          {}\n", OptionalHeader->MajorSubsystemVersion);
    std::cout << std::format("\tMinorSubsystemVersion:          {}\n", OptionalHeader->MinorSubsystemVersion);
    std::cout << std::format("\tWin32VersionValue:              {}\n", OptionalHeader->Win32VersionValue);
    std::cout << std::format("\tSizeOfImage:                    {}\n", OptionalHeader->SizeOfImage);
    std::cout << std::format("\tSizeOfHeaders:                  {}\n", OptionalHeader->SizeOfHeaders);
    std::cout << std::format("\tCheckSum:                       {:#010x}\n", OptionalHeader->CheckSum);
    std::cout << std::format("\tSubsystem:                      {} ({})\n", OptionalHeader->Subsystem, GetSubsystemFromValue(OptionalHeader->Subsystem));
    std::cout << std::format("\tDllCharacteristics:             {:#18b}\n", OptionalHeader->DLLCharacteristics);

    for (uint32_t j = 1; j < (1 << 16); j <<= 1)
    {
        std::string characteristic = GetDllCharacteristicsFromValue(OptionalHeader->DLLCharacteristics & j);
        if (!characteristic.empty())
            std::cout << std::format("\t\t{}\n", characteristic);
    }

    std::cout << std::format("\tSizeOfStackReserve:             {}\n", OptionalHeader->SizeOfStackReserve);
    std::cout << std::format("\tSizeOfStackCommit:              {}\n", OptionalHeader->SizeOfStackCommit);
    std::cout << std::format("\tSizeOfHeapReserve:              {}\n", OptionalHeader->SizeOfHeapReserve);
    std::cout << std::format("\tSizeOfHeapCommit:               {}\n", OptionalHeader->SizeOfHeapCommit);
    std::cout << std::format("\tLoaderFlags:                    {}\n", OptionalHeader->LoaderFlags);
    std::cout << std::format("\tNumberOfRvaAndSize:             {}\n\n", OptionalHeader->NumberOfRvaAndSizes);
}

void PEImage::PrintDataDirectories() const
{
    std::cout << "[*] Data Directories\n";

    for (uint32_t i = 0; i < DataDirectoriesCount; i++)
    {
        std::cout << std::format("\t{}\n", GetDataDirectoryNameFromValue(i));
        std::cout << std::format("\t\tVirtualAddress:   {:#010x}\n", DataDirectory[i].VirtualAddress);
        std::cout << std::format("\t\tSize:             {}\n", DataDirectory[i].Size);
    }
}

void PEImage::PrintSectionTables() const
{
    std::cout << "\n[*] Image Section Headers\n";
    for (uint16_t i = 0; i < SectionHeaderCount; i++)
    {
        std::cout << std::format("\tName: {:.8s}\n", SectionHeader[i].Name);
        std::cout << std::format("\t\tVirtualSize:          {0:#010x} ({0})\n", SectionHeader[i].VirtualSize);
        std::cout << std::format("\t\tVirtalAddress:        {:#010x}\n", SectionHeader[i].VirtualAddress);
        std::cout << std::format("\t\tSizeOfRawData:        {0:#010x} ({0})\n", SectionHeader[i].SizeOfRawData);
        std::cout << std::format("\t\tPointerToRawData:     {:#010x}\n", SectionHeader[i].PointerToRawData);
        std::cout << std::format("\t\tPointerToRelocations: {:#010x}\n", SectionHeader[i].PointerToRelocations);
        std::cout << std::format("\t\tPointerToLineNumbers: {:#010x}\n", SectionHeader[i].PointerToLineNumbers);
        std::cout << std::format("\t\tNumberOfRelocations:  {}\n", SectionHeader[i].NumberOfRelocations);
        std::cout << std::format("\t\tNumberOfLineNumbers:  {}\n", SectionHeader[i].NumberOfLineNumbers);
        std::cout << std::format("\t\tCharacteristics:      {:#034b}\n", SectionHeader[i].Characteristics);

        for (uint64_t j = 1; j < (static_cast<uint64_t>(1) << 32); j <<= 1)
        {
            std::string characteristic = GetSectionCharacteristicsFromValue(SectionHeader[i].Characteristics & j);
            if (!characteristic.empty())
                std::cout << std::format("\t\t\t{}\n", characteristic);
        }

        std::cout << '\n';
    }
}