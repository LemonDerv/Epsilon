/**
 * 
 *
 * A command-line utility that modifies an existing Portable Executable
 * (PE) file on disk:
 *
 *   1. Parses the DOS / NT / Section headers.
 *   2. Appends a new section (.instr) with RWX permissions.
 *   3. Injects a caller-supplied byte stub into the new section.
 *   4. Redirects AddressOfEntryPoint to the new section.
 *   5. Stores the original entry point in OptionalHeader.LoaderFlags
 *      so the stub can resume the original program.
 *
 * Build (MSVC):
 *   cl /EHsc /W4 /std:c++17 PeInstrument.cpp /Fe:PeInstrument.exe
 *
 * Build (MinGW):
 *   g++ -std=c++17 -Wall -o PeInstrument.exe PeInstrument.cpp
 *
 * Usage:
 *   PeInstrument.exe <target.exe>
 */

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>

#include <windows.h>

/* ------------------------------------------------------------------ */
/*  Configuration constants                                           */
/* ------------------------------------------------------------------ */

/// Name of the section we inject (8-byte padded, null-terminated).
static const char  NEW_SECTION_NAME[IMAGE_SIZEOF_SHORT_NAME] = ".instr";

/// Default virtual size we reserve for the new section.
static constexpr DWORD  NEW_SECTION_VIRTUAL_SIZE = 0x1000;

/// Section characteristics: readable | writable | executable | contains code.
static constexpr DWORD  NEW_SECTION_CHARACTERISTICS =
    IMAGE_SCN_MEM_READ  |
    IMAGE_SCN_MEM_WRITE |
    IMAGE_SCN_MEM_EXECUTE |
    IMAGE_SCN_CNT_CODE;

/* ------------------------------------------------------------------ */
/*  Helper: align a value up to the nearest multiple of Alignment.    */
/* ------------------------------------------------------------------ */

static inline DWORD
AlignUp (DWORD Value, DWORD Alignment)
{
    return (Value + Alignment - 1) & ~(Alignment - 1);
}

/* ------------------------------------------------------------------ */
/*  ReadFileToBuffer / WriteBufferToFile — raw I/O helpers            */
/* ------------------------------------------------------------------ */

/**
 * Read the entire contents of a file into a byte vector.
 *
 * @param[in]  Path    Path to the file.
 * @param[out] Buffer  Receives the file contents.
 *
 * @return true on success, false on failure.
 */
static bool
ReadFileToBuffer (const std::string &Path, std::vector<uint8_t> &Buffer)
{
    FILE *f = fopen (Path.c_str (), "rb");
    if (!f) {
        fprintf (stderr, "[!] Cannot open '%s' for reading.\n", Path.c_str ());
        return false;
    }

    fseek (f, 0, SEEK_END);
    long Size = ftell (f);
    fseek (f, 0, SEEK_SET);

    if (Size <= 0) {
        fclose (f);
        return false;
    }

    Buffer.resize (static_cast<size_t> (Size));
    size_t BytesRead = fread (Buffer.data (), 1, Buffer.size (), f);
    fclose (f);

    return BytesRead == Buffer.size ();
}

/**
 * Write a byte buffer back to a file, replacing its contents.
 *
 * @param[in] Path    Path to the file.
 * @param[in] Buffer  Data to write.
 *
 * @return true on success.
 */
static bool
WriteBufferToFile (const std::string &Path, const std::vector<uint8_t> &Buffer)
{
    FILE *f = fopen (Path.c_str (), "wb");
    if (!f) {
        fprintf (stderr, "[!] Cannot open '%s' for writing.\n", Path.c_str ());
        return false;
    }

    size_t Written = fwrite (Buffer.data (), 1, Buffer.size (), f);
    fclose (f);

    return Written == Buffer.size ();
}

/* ------------------------------------------------------------------ */
/*  Core: InjectSection                                               */
/* ------------------------------------------------------------------ */

/**
 * Inject a new code section into a PE image buffer.
 *
 * Detailed steps:
 *   1. Validate DOS and NT headers.
 *   2. Ensure there is room for one more section header.
 *   3. Populate the new IMAGE_SECTION_HEADER.
 *   4. Append the stub payload (zero-padded to FileAlignment).
 *   5. Save the original AddressOfEntryPoint in LoaderFlags.
 *   6. Redirect AddressOfEntryPoint to the new section RVA.
 *   7. Update SizeOfImage to account for the new section.
 *
 * @param[in,out] Buffer   The PE file contents (may be resized).
 * @param[in]     Stub     The instrumentation shellcode to inject.
 * @param[in]     StubSize Size of the shellcode in bytes.
 *
 * @return true on success, false on any validation failure.
 */
static bool
InjectSection (
    std::vector<uint8_t> &Buffer,
    const uint8_t        *Stub,
    size_t                StubSize
    )
{
    /* ------------------------------------------------------------ */
    /*  Step 1 — Locate and validate the PE headers                 */
    /* ------------------------------------------------------------ */

    if (Buffer.size () < sizeof (IMAGE_DOS_HEADER)) {
        fprintf (stderr, "[!] File too small for a DOS header.\n");
        return false;
    }

    auto *DosHdr = reinterpret_cast<IMAGE_DOS_HEADER *> (Buffer.data ());

    if (DosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf (stderr, "[!] Invalid DOS signature (expected 'MZ').\n");
        return false;
    }

    if (static_cast<size_t> (DosHdr->e_lfanew) + sizeof (IMAGE_NT_HEADERS) > Buffer.size ()) {
        fprintf (stderr, "[!] e_lfanew points outside the file.\n");
        return false;
    }

    auto *NtHdrs = reinterpret_cast<IMAGE_NT_HEADERS *> (
                       Buffer.data () + DosHdr->e_lfanew);

    if (NtHdrs->Signature != IMAGE_NT_SIGNATURE) {
        fprintf (stderr, "[!] Invalid NT signature (expected 'PE\\0\\0').\n");
        return false;
    }

    IMAGE_FILE_HEADER    &FileHdr = NtHdrs->FileHeader;
    IMAGE_OPTIONAL_HEADER &OptHdr = NtHdrs->OptionalHeader;

    DWORD FileAlignment    = OptHdr.FileAlignment;
    DWORD SectionAlignment = OptHdr.SectionAlignment;

    printf ("[*] FileAlignment    = 0x%X\n", FileAlignment);
    printf ("[*] SectionAlignment = 0x%X\n", SectionAlignment);
    printf ("[*] Original entry   = 0x%08X\n", OptHdr.AddressOfEntryPoint);
    printf ("[*] Existing sections: %u\n",     FileHdr.NumberOfSections);

    /* ------------------------------------------------------------ */
    /*  Step 2 — Verify room for a new section header               */
    /*                                                               */
    /*  Section headers follow the Optional Header and must fit      */
    /*  before the first section's raw data begins.                  */
    /* ------------------------------------------------------------ */

    auto *FirstSection = IMAGE_FIRST_SECTION (NtHdrs);
    auto *LastSection  = &FirstSection[FileHdr.NumberOfSections - 1];

    //
    // Position where the new section header would be written.
    //
    size_t NewHeaderOffset =
        reinterpret_cast<uintptr_t> (LastSection + 1) -
        reinterpret_cast<uintptr_t> (Buffer.data ());

    size_t NewHeaderEnd = NewHeaderOffset + sizeof (IMAGE_SECTION_HEADER);

    //
    // Earliest raw-data start among all existing sections.
    //
    DWORD EarliestRawData = FirstSection->PointerToRawData;
    for (WORD i = 0; i < FileHdr.NumberOfSections; i++) {
        if (FirstSection[i].PointerToRawData &&
            FirstSection[i].PointerToRawData < EarliestRawData) {
            EarliestRawData = FirstSection[i].PointerToRawData;
        }
    }

    if (NewHeaderEnd > EarliestRawData) {
        fprintf (stderr, "[!] No room for an additional section header.\n");
        fprintf (stderr, "    Header would end at 0x%zX, but raw data starts at 0x%X.\n",
                 NewHeaderEnd, EarliestRawData);
        return false;
    }

    /* ------------------------------------------------------------ */
    /*  Step 3 — Compute the new section's RVA and file offset      */
    /* ------------------------------------------------------------ */

    DWORD LastSectionEndRVA =
        AlignUp (LastSection->VirtualAddress + LastSection->Misc.VirtualSize,
                 SectionAlignment);

    DWORD LastSectionEndRaw =
        AlignUp (LastSection->PointerToRawData + LastSection->SizeOfRawData,
                 FileAlignment);

    DWORD NewSectionRVA      = LastSectionEndRVA;
    DWORD NewSectionRawOff   = LastSectionEndRaw;
    DWORD NewSectionRawSize  = AlignUp (static_cast<DWORD> (StubSize), FileAlignment);
    DWORD NewSectionVirtSize = (StubSize > NEW_SECTION_VIRTUAL_SIZE)
                                   ? static_cast<DWORD> (StubSize)
                                   : NEW_SECTION_VIRTUAL_SIZE;

    printf ("[*] New section RVA      = 0x%08X\n", NewSectionRVA);
    printf ("[*] New section raw off  = 0x%08X\n", NewSectionRawOff);
    printf ("[*] New section raw size = 0x%08X\n", NewSectionRawSize);

    /* ------------------------------------------------------------ */
    /*  Step 4 — Populate the new section header                    */
    /* ------------------------------------------------------------ */

    IMAGE_SECTION_HEADER NewSec = {};
    memcpy (NewSec.Name, NEW_SECTION_NAME, IMAGE_SIZEOF_SHORT_NAME);
    NewSec.Misc.VirtualSize  = NewSectionVirtSize;
    NewSec.VirtualAddress    = NewSectionRVA;
    NewSec.SizeOfRawData     = NewSectionRawSize;
    NewSec.PointerToRawData  = NewSectionRawOff;
    NewSec.Characteristics   = NEW_SECTION_CHARACTERISTICS;

    //
    // Write the header into the buffer (we already verified there is room).
    //
    memcpy (Buffer.data () + NewHeaderOffset, &NewSec, sizeof (NewSec));

    /* ------------------------------------------------------------ */
    /*  Step 5 — Append the stub payload to the file                */
    /* ------------------------------------------------------------ */

    //
    // Grow the file so it covers [NewSectionRawOff, NewSectionRawOff + NewSectionRawSize).
    //
    size_t RequiredSize = static_cast<size_t> (NewSectionRawOff) + NewSectionRawSize;
    if (Buffer.size () < RequiredSize) {
        Buffer.resize (RequiredSize, 0x00);   // Zero-fill any gap
    }

    //
    // Copy the instrumentation stub into the new section.
    //
    memcpy (Buffer.data () + NewSectionRawOff, Stub, StubSize);

    /* ------------------------------------------------------------ */
    /*  Step 6 — Save original EP in LoaderFlags, redirect EP       */
    /* ------------------------------------------------------------ */

    //
    // Re-acquire pointers — the resize above may have invalidated them.
    //
    DosHdr = reinterpret_cast<IMAGE_DOS_HEADER *> (Buffer.data ());
    NtHdrs = reinterpret_cast<IMAGE_NT_HEADERS *> (Buffer.data () + DosHdr->e_lfanew);

    //
    // LoaderFlags is reserved/unused by modern loaders — a convenient
    // place for the stub to read the original entry point at runtime:
    //
    //   DWORD OriginalEP = NtHeaders->OptionalHeader.LoaderFlags;
    //
    NtHdrs->OptionalHeader.LoaderFlags       = NtHdrs->OptionalHeader.AddressOfEntryPoint;
    NtHdrs->OptionalHeader.AddressOfEntryPoint = NewSectionRVA;

    printf ("[*] Original EP saved to LoaderFlags = 0x%08X\n",
            NtHdrs->OptionalHeader.LoaderFlags);
    printf ("[*] New AddressOfEntryPoint           = 0x%08X\n",
            NtHdrs->OptionalHeader.AddressOfEntryPoint);

    /* ------------------------------------------------------------ */
    /*  Step 7 — Update header counters                             */
    /* ------------------------------------------------------------ */

    NtHdrs->FileHeader.NumberOfSections += 1;

    NtHdrs->OptionalHeader.SizeOfImage =
        AlignUp (NewSectionRVA + NewSectionVirtSize, SectionAlignment);

    printf ("[*] Updated SizeOfImage = 0x%08X\n",
            NtHdrs->OptionalHeader.SizeOfImage);

    return true;
}

/* ------------------------------------------------------------------ */
/*  main                                                              */
/* ------------------------------------------------------------------ */

int
main (int argc, char *argv[])
{
    if (argc < 2) {
        fprintf (stderr, "Usage: %s <target.exe>\n", argv[0]);
        return 1;
    }

    const std::string TargetPath (argv[1]);

    /* -------------------------------------------------------------- */
    /*  Demo instrumentation stub (x64)                               */
    /*                                                                */
    /*  This minimal stub does the following:                         */
    /*    1. NOP sled (placeholder for your real instrumentation).    */
    /*    2. Reads the original EP from the PE header's LoaderFlags.  */
    /*                                                                */
    /*  In a real packer you would compute ImageBase + OriginalEP    */
    /*  and JMP there.  This stub is intentionally skeletal.          */
    /* -------------------------------------------------------------- */

    static const uint8_t DemoStub[] = {
        //
        // --- Placeholder: 16 NOPs (insert real instrumentation here) ---
        //
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,

        //
        // --- Compute original entry point and jump ---
        //
        // The real stub would:
        //   1. Get its own ImageBase (via PEB or RIP-relative addressing).
        //   2. Walk to OptionalHeader.LoaderFlags to read the saved EP.
        //   3. Add ImageBase + LoaderFlags to get the absolute VA.
        //   4. JMP to that address.
        //
        // For now: INT3 (breakpoint) as a placeholder for debugging.
        //
        0xCC
    };

    /* -------------------------------------------------------------- */
    /*  Read → Instrument → Write-back                                */
    /* -------------------------------------------------------------- */

    std::vector<uint8_t> FileBuffer;

    if (!ReadFileToBuffer (TargetPath, FileBuffer)) {
        return 1;
    }

    printf ("[*] Loaded '%s' (%zu bytes).\n", TargetPath.c_str (), FileBuffer.size ());

    if (!InjectSection (FileBuffer, DemoStub, sizeof (DemoStub))) {
        fprintf (stderr, "[!] Section injection failed.\n");
        return 1;
    }

    if (!WriteBufferToFile (TargetPath, FileBuffer)) {
        return 1;
    }

    printf ("[+] Instrumented PE written back to '%s' (%zu bytes).\n",
            TargetPath.c_str (), FileBuffer.size ());

    return 0;
}
