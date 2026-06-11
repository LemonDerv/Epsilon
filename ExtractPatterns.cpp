#include <windows.h>
#include <dbghelp.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <string>

#pragma comment(lib, "dbghelp.lib")

/**
 * Parses the PE headers to translate a Relative Virtual Address (RVA) 
 * into a physical file offset.
 */
DWORD RvaToFileOffset(const std::string& filepath, DWORD rva) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        return 0;
    }

    IMAGE_DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    file.seekg(dosHeader.e_lfanew, std::ios::beg);
    DWORD signature;
    file.read(reinterpret_cast<char*>(&signature), sizeof(signature));
    if (signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    IMAGE_FILE_HEADER fileHeader;
    file.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));

    // Jump past the Optional Header directly to the Section Headers
    file.seekg(dosHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader, std::ios::beg);

    for (int i = 0; i < fileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER sectionHeader;
        file.read(reinterpret_cast<char*>(&sectionHeader), sizeof(sectionHeader));

        // Take the VirtualSize, or SizeOfRawData if VirtualSize is 0
        DWORD sectionSize = sectionHeader.Misc.VirtualSize ? sectionHeader.Misc.VirtualSize : sectionHeader.SizeOfRawData;

        if (rva >= sectionHeader.VirtualAddress && rva < sectionHeader.VirtualAddress + sectionSize) {
            return sectionHeader.PointerToRawData + (rva - sectionHeader.VirtualAddress);
        }
    }
    return 0;
}

void PrintPattern(const std::string& name, const std::string& filepath, DWORD offset) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file || offset == 0) {
        std::cerr << "[-] Failed to open file or invalid offset for " << name << "\n";
        return;
    }

    file.seekg(offset, std::ios::beg);
    unsigned char bytes[12];
    file.read(reinterpret_cast<char*>(bytes), sizeof(bytes));

    std::cout << "STATIC CONST UINT8 Pattern_" << name << "[] = { ";
    for (int i = 0; i < 12; ++i) {
        std::cout << "0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)bytes[i];
        if (i < 11) std::cout << ", ";
    }
    std::cout << " };\n";
}

int main() {
    std::cout << "[*] Initializing DbgHelp and MS Symbol Server...\n";

    // Ensure the local symbol cache directory exists to prevent path errors
    CreateDirectoryA("C:\\Symbols", NULL);

    HANDLE hProcess = GetCurrentProcess();
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
    
    std::string symbolPath = "SRV*C:\\Symbols*https://msdl.microsoft.com/download/symbols";
    if (!SymInitialize(hProcess, symbolPath.c_str(), FALSE)) {
        std::cerr << "[-] SymInitialize failed: " << GetLastError() << "\n";
        return 1;
    }

    std::string filepath = "C:\\Windows\\System32\\boot\\winload.efi";
    DWORD64 baseAddress = 0x10000000; // Arbitrary base for RVA calculation
    DWORD64 moduleAddress = SymLoadModuleEx(hProcess, NULL, filepath.c_str(), NULL, baseAddress, 0, NULL, 0);

    if (!moduleAddress) {
        std::cerr << "[-] SymLoadModuleEx failed: " << GetLastError() << "\n";
        SymCleanup(hProcess);
        return 1;
    }

    char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
    PSYMBOL_INFO pSymbol = reinterpret_cast<PSYMBOL_INFO>(buffer);
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = MAX_SYM_NAME;

    const char* targets[] = { "ImgpValidateImageHash", "ImgpLoadPEImage" };

    for (const char* target : targets) {
        if (SymFromName(hProcess, target, pSymbol)) {
            DWORD rva = static_cast<DWORD>(pSymbol->Address - baseAddress);
            DWORD offset = RvaToFileOffset(filepath, rva);
            
            std::cout << "[+] Found " << target << " (RVA: 0x" << std::hex << rva << ", File Offset: 0x" << offset << ")\n";
            if (offset != 0) PrintPattern(target, filepath, offset);
        } else {
            DWORD err = GetLastError();
            std::cerr << "[-] SymFromName failed for " << target << ": " << err << "\n";
            if (err == 126) {
                std::cerr << "    [!] ERROR_MOD_NOT_FOUND: symsrv.dll is missing from your working directory.\n";
            }
        }
        std::cout << "\n";
    }

    SymUnloadModule64(hProcess, moduleAddress);
    SymCleanup(hProcess);
    
    std::cout << "Done.\n";
    return 0;
}