#include "ntddk.h"
#include <intrin.h>   // __readcr3, __writecr3

/* ================================================================== */
/*  Configuration                                                     */
/* ================================================================== */

/**
 * The Thread ID we want to isolate.  When the kernel is about to
 * context-switch TO this thread, we swap CR3 to our cloned PML4.
 *
 * In a real driver you would expose an IOCTL to set this dynamically.
 */
#define TARGET_THREAD_ID  ((HANDLE)(ULONG_PTR)1234)

/**
 * Example structure for .data pointer hook communication.
 */
typedef struct _COMM_DATA {
    ULONG64 TargetAddress;
    ULONG64 Buffer;
    ULONG   Size;
    ULONG   Operation; // 0 = Read, 1 = Write
    ULONG   Magic;     // Sentinel value
} COMM_DATA, *PCOMM_DATA;

/* ================================================================== */
/*  PML4 / Paging definitions (x86-64, 4-level paging)               */
/* ================================================================== */

/// Number of entries in a single paging table (PML4, PDPT, PD, PT).
#define PML4_ENTRY_COUNT  512

/// Size of a full paging table in bytes (4 KiB).
#define PAGE_TABLE_SIZE   (PML4_ENTRY_COUNT * sizeof(UINT64))

/// Mask to extract the physical Page-Frame Number from CR3.
/// Bits [12:51] contain the PFN on Intel; bits [0:11] are flags.
#define CR3_PFN_MASK      0x000FFFFFFFFFF000ULL

/**
 * A single PML4 entry (PML4E) is a 64-bit value:
 *
 *   Bit 0     : Present (P)
 *   Bit 1     : Read/Write (R/W)
 *   Bit 2     : User/Supervisor (U/S)
 *   Bit 3     : Page-Level Write-Through (PWT)
 *   Bit 4     : Page-Level Cache Disable (PCD)
 *   Bit 5     : Accessed (A)
 *   Bits 12-51: Physical address of the referenced PDPT
 *   Bit 63    : Execute Disable (XD/NX)
 */
typedef UINT64 PML4E;

/* ================================================================== */
/*  Globals                                                           */
/* ================================================================== */

/// Physical address of our cloned PML4 table (0 = not yet allocated).
static PHYSICAL_ADDRESS  gClonedPml4Physical  = { 0 };

/// Virtual mapping of the cloned PML4 table.
static PML4E            *gClonedPml4Virtual   = NULL;

/// Original bytes overwritten by the SwapContext inline hook.
/// 14 bytes is enough for a 64-bit absolute JMP (FF 25 00000000 + 8-byte addr).
#define HOOK_STUB_SIZE    14
static UINT8             gOriginalBytes[HOOK_STUB_SIZE];

/// Address of nt!SwapContext (resolved at runtime).
static PVOID             gSwapContextAddress  = NULL;

/// Original function pointer from the hooked .data section.
static PVOID             gOriginalDataPointer = NULL;

/* ================================================================== */
/*  Intrinsics wrappers — CR3 access                                  */
/* ================================================================== */

/**
 * Read the current value of CR3.
 */
static __forceinline UINT64
ReadCr3 (VOID)
{
    return __readcr3 ();
}

/**
 * Write a new value to CR3, which immediately flushes the TLB.
 *
 * @param[in] NewCr3  The new CR3 value (physical address of PML4 | flags).
 */
static __forceinline VOID
WriteCr3 (UINT64 NewCr3)
{
    __writecr3 (NewCr3);
}

/* ================================================================== */
/*  Physical ↔ Virtual helpers                                        */
/* ================================================================== */

/**
 * Map a physical address range into kernel virtual address space.
 *
 * @param[in] PhysAddr  Physical address to map.
 * @param[in] Size      Number of bytes to map.
 *
 * @return  Kernel VA, or NULL on failure.
 */
static PVOID
MapPhysical (PHYSICAL_ADDRESS PhysAddr, SIZE_T Size)
{
    return MmMapIoSpace (PhysAddr, Size, MmNonCached);
}

/**
 * Unmap a previous MmMapIoSpace mapping.
 */
static VOID
UnmapPhysical (PVOID VirtAddr, SIZE_T Size)
{
    MmUnmapIoSpace (VirtAddr, Size);
}

/* ================================================================== */
/*  ClonePml4 — allocate a new PML4 and shallow-copy entries          */
/* ================================================================== */

/**
 * Allocate a new 4 KiB–aligned physical page, map it, and copy
 * all 512 PML4 entries from the currently active PML4.
 *
 * A "shallow clone" means we copy the PML4 entries verbatim.
 * The lower-level tables (PDPT, PD, PT) are still shared with the
 * original address space.  This is sufficient for exercises that
 * only need per-thread PML4-level isolation (e.g., unmapping a
 * single 512 GiB region in one thread's view).
 *
 * @return STATUS_SUCCESS or an error NTSTATUS.
 */
static NTSTATUS
ClonePml4 (VOID)
{
    UINT64            Cr3;
    PHYSICAL_ADDRESS  OrigPml4Phys;
    PML4E            *OrigPml4Virt;
    PHYSICAL_ADDRESS  LowAddr  = { 0 };
    PHYSICAL_ADDRESS  HighAddr;
    PHYSICAL_ADDRESS  Skip     = { 0 };

    //
    // If already allocated, nothing to do.
    //
    if (gClonedPml4Virtual != NULL) {
        return STATUS_SUCCESS;
    }

    /* ------------------------------------------------------------ */
    /*  Read CR3 → extract PML4 physical address                    */
    /* ------------------------------------------------------------ */

    Cr3 = ReadCr3 ();
    OrigPml4Phys.QuadPart = (LONGLONG)(Cr3 & CR3_PFN_MASK);

    DbgPrint ("[PagingHook] Current CR3        = 0x%016llX\n", Cr3);
    DbgPrint ("[PagingHook] Original PML4 phys = 0x%016llX\n",
              OrigPml4Phys.QuadPart);

    /* ------------------------------------------------------------ */
    /*  Map the original PML4 into kernel VA so we can read it      */
    /* ------------------------------------------------------------ */

    OrigPml4Virt = (PML4E *)MapPhysical (OrigPml4Phys, PAGE_TABLE_SIZE);
    if (OrigPml4Virt == NULL) {
        DbgPrint ("[PagingHook] Failed to map original PML4.\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* ------------------------------------------------------------ */
    /*  Allocate a contiguous 4 KiB physical page for the clone     */
    /* ------------------------------------------------------------ */

    HighAddr.QuadPart = 0xFFFFFFFFLL;  // Below 4 GiB for safety

    gClonedPml4Virtual = (PML4E *)MmAllocateContiguousMemorySpecifyCache (
                             PAGE_TABLE_SIZE,
                             LowAddr,
                             HighAddr,
                             Skip,
                             MmNonCached
                             );

    if (gClonedPml4Virtual == NULL) {
        DbgPrint ("[PagingHook] Failed to allocate cloned PML4 page.\n");
        UnmapPhysical (OrigPml4Virt, PAGE_TABLE_SIZE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Retrieve the physical address of the cloned page.
    //
    gClonedPml4Physical = MmGetPhysicalAddress (gClonedPml4Virtual);

    DbgPrint ("[PagingHook] Cloned PML4 phys   = 0x%016llX\n",
              gClonedPml4Physical.QuadPart);

    /* ------------------------------------------------------------ */
    /*  Copy all 512 PML4 entries (shallow clone)                   */
    /* ------------------------------------------------------------ */

    RtlCopyMemory (gClonedPml4Virtual, OrigPml4Virt, PAGE_TABLE_SIZE);

    /*
     * OPTIONAL: At this point you can modify individual PML4 entries
     * in gClonedPml4Virtual to unmap or remap specific 512 GiB regions
     * for the target thread.  For example:
     *
     *   gClonedPml4Virtual[256] = 0;  // Remove the first user-mode
     *                                 // 512 GiB mapping
     */

    /* ------------------------------------------------------------ */
    /*  Unmap the original PML4 mapping (no longer needed)          */
    /* ------------------------------------------------------------ */

    UnmapPhysical (OrigPml4Virt, PAGE_TABLE_SIZE);

    return STATUS_SUCCESS;
}

/* ================================================================== */
/*  SwapContext hook logic                                             */
/* ================================================================== */

/**
 * This function encapsulates the logic that would execute inside the
 * SwapContext hook callback.
 *
 * In a real inline-hook scenario, the trampoline would:
 *   1. Save all volatile registers.
 *   2. Call this function.
 *   3. Restore registers and jump to the remainder of the original
 *      SwapContext.
 *
 * @param[in] NewThread  ETHREAD pointer of the thread being switched TO.
 *                       On amd64 Windows, SwapContext receives the new
 *                       thread in RSI (varies by Windows version).
 */
static VOID
OnSwapContext (PETHREAD NewThread)
{
    HANDLE   Tid;
    UINT64   CurrentCr3;
    UINT64   NewCr3;

    if (NewThread == NULL) {
        return;
    }

    /* ------------------------------------------------------------ */
    /*  Determine the Thread ID of the incoming thread              */
    /* ------------------------------------------------------------ */

    Tid = PsGetThreadId (NewThread);

    /* ------------------------------------------------------------ */
    /*  Only intervene for our target TID                           */
    /* ------------------------------------------------------------ */

    if (Tid != TARGET_THREAD_ID) {
        //
        // Not our thread — ensure we are using the *original* CR3.
        // If this CPU previously ran our target thread, CR3 may still
        // point to the clone.  Restore it from the process' DirectoryBase.
        //
        // In practice you would cache the original CR3 per-CPU.
        //
        return;
    }

    /* ------------------------------------------------------------ */
    /*  Lazy-initialise the cloned PML4 on first hit                */
    /* ------------------------------------------------------------ */

    if (gClonedPml4Virtual == NULL) {
        NTSTATUS Status = ClonePml4 ();
        if (!NT_SUCCESS (Status)) {
            DbgPrint ("[PagingHook] ClonePml4 failed: 0x%08X\n", Status);
            return;
        }
    }

    /* ------------------------------------------------------------ */
    /*  Swap CR3 to point to our cloned PML4                        */
    /* ------------------------------------------------------------ */

    CurrentCr3 = ReadCr3 ();

    //
    // Preserve the flag bits from the original CR3 (PCID, PWT, PCD).
    //
    NewCr3 = (gClonedPml4Physical.QuadPart & CR3_PFN_MASK) |
             (CurrentCr3 & ~CR3_PFN_MASK);

    DbgPrint ("[PagingHook] TID %p: CR3 0x%016llX -> 0x%016llX\n",
              Tid, CurrentCr3, NewCr3);

    WriteCr3 (NewCr3);
}

/* ================================================================== */
/*  Shellcode Utility Functions (PIC Friendly)                        */
/* ================================================================== */

/**
 * Find the base address of ntoskrnl.exe by scanning memory backwards 
 * from a known kernel address (like a stack return address).
 */
static PVOID
FindNtoskrnlBase (PVOID AnyKernelAddr)
{
    ULONG_PTR CheckAddr = (ULONG_PTR)AnyKernelAddr & ~(0xFFF);
    while (CheckAddr > 0xFFFF800000000000ULL) {
        if (*(USHORT*)CheckAddr == 0x5A4D) { // 'MZ'
            return (PVOID)CheckAddr;
        }
        CheckAddr -= 0x1000;
    }
    return NULL;
}

/**
 * Simple pattern scanner to find unexported symbols.
 */
static PVOID
FindPattern (PVOID Base, ULONG Size, const UCHAR* Pattern, const char* Mask)
{
    ULONG Len = (ULONG)strlen(Mask);
    for (ULONG i = 0; i < Size - Len; i++) {
        BOOLEAN Match = TRUE;
        for (ULONG j = 0; j < Len; j++) {
            if (Mask[j] == 'x' && ((UCHAR*)Base)[i + j] != Pattern[j]) {
                Match = FALSE;
                break;
            }
        }
        if (Match) return (PVOID)((UCHAR*)Base + i);
    }
    return NULL;
}

/* ================================================================== */
/*  Inline Hook Installation / Removal                                */
/* ================================================================== */

/**
 * Reliable resolution of nt!SwapContext via pattern scanning.
 * Signature: 48 8b 05 ? ? ? ? 48 8d 0d ? ? ? ? 45 33 c0
 * WARNING: The address changes across OS builds.  A production
 * implementation would parse the PDB or use pattern scanning.
 *
 * @return Pointer to SwapContext, or NULL if not found.
 */
static PVOID
ResolveSwapContext (VOID)
{
    // Example signature for SwapContext on Win10/11
    const UCHAR Signature[] = { 0x48, 0x8b, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x0d };
    const char* Mask = "xxx????xxx";

    PVOID NtosBase = FindNtoskrnlBase((PVOID)DbgPrint); 
    if (!NtosBase) return NULL;

    // Scan a reasonable range of the .text section
    return FindPattern(NtosBase, 0x1000000, Signature, Mask);
}

/**
 * Install an inline JMP hook at the beginning of SwapContext.
 *
 * Hook format (14 bytes, position-independent absolute JMP):
 *
 *   FF 25 00 00 00 00        jmp  qword ptr [rip+0]
 *   <8-byte absolute address of our detour>
 *
 * @return STATUS_SUCCESS or an error code.
 */
static NTSTATUS
InstallSwapContextHook (VOID)
{
    UINT8   HookBytes[HOOK_STUB_SIZE];
    UINT64  DetourAddr;

    gSwapContextAddress = ResolveSwapContext ();
    if (gSwapContextAddress == NULL) {
        DbgPrint ("[PagingHook] Could not resolve SwapContext.\n");
        return STATUS_NOT_FOUND;
    }

    DbgPrint ("[PagingHook] SwapContext @ %p\n", gSwapContextAddress);

    //
    // Save the original bytes so we can unhook later.
    //
    RtlCopyMemory (gOriginalBytes, gSwapContextAddress, HOOK_STUB_SIZE);

    //
    // Build the 14-byte absolute JMP stub.
    //
    HookBytes[0] = 0xFF;
    HookBytes[1] = 0x25;
    *(UINT32 *)&HookBytes[2] = 0x00000000;   // RIP+0 offset

    DetourAddr = (UINT64)(ULONG_PTR)OnSwapContext;
    *(UINT64 *)&HookBytes[6] = DetourAddr;

    //
    // Disable write-protection (CR0.WP) briefly to patch the
    // read-only kernel .text section.
    //
    // WARNING: Disabling WP is extremely dangerous and is shown
    //          here purely for educational purposes.
    //
    {
        KIRQL OldIrql;
        UINT64 Cr0;

        OldIrql = KeRaiseIrqlToDpcLevel ();

        Cr0 = __readcr0 ();
        __writecr0 (Cr0 & ~(1ULL << 16));   // Clear WP bit

        RtlCopyMemory (gSwapContextAddress, HookBytes, HOOK_STUB_SIZE);

        __writecr0 (Cr0);                   // Restore WP bit

        KeLowerIrql (OldIrql);
    }

    DbgPrint ("[PagingHook] SwapContext hook installed.\n");
    return STATUS_SUCCESS;
}

/**
 * Remove the inline hook by restoring the original bytes.
 */
static VOID
RemoveSwapContextHook (VOID)
{
    if (gSwapContextAddress == NULL) {
        return;
    }

    {
        KIRQL OldIrql;
        UINT64 Cr0;

        OldIrql = KeRaiseIrqlToDpcLevel ();

        Cr0 = __readcr0 ();
        __writecr0 (Cr0 & ~(1ULL << 16));

        RtlCopyMemory (gSwapContextAddress, gOriginalBytes, HOOK_STUB_SIZE);

        __writecr0 (Cr0);

        KeLowerIrql (OldIrql);
    }

    gSwapContextAddress = NULL;
    DbgPrint ("[PagingHook] SwapContext hook removed.\n");
}

/* ================================================================== */
/*  System Thread Communication Bridge                                */
/* ================================================================== */

// Globals
volatile PCOMM_DATA g_SharedBuffer = NULL;

VOID SharedMemoryThread(PVOID StartContext) {
    UNREFERENCED_PARAMETER(StartContext);
    LARGE_INTEGER delay;
    delay.QuadPart = -10000000; // 1 second

    HANDLE ClientPID = NULL;
    PVOID UmAddress = NULL;
    
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING KeyName;
    RtlInitUnicodeString(&KeyName, L"\\Registry\\Machine\\SOFTWARE\\Elysium");
    InitializeObjectAttributes(&ObjectAttributes, &KeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    DbgPrint("[PagingHook] SharedMemoryThread started. Waiting for UM Client...\n");

    // 1. Poll the Registry until the UM Client writes the keys
    while (TRUE) {
        HANDLE KeyHandle;
        if (NT_SUCCESS(ZwOpenKey(&KeyHandle, KEY_READ | KEY_WRITE | DELETE, &ObjectAttributes))) {
            
            ULONG resultLength;
            
            // Query ClientPID
            UNICODE_STRING ValNamePid;
            RtlInitUnicodeString(&ValNamePid, L"ClientPID");
            UCHAR pidBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(DWORD)];
            if (NT_SUCCESS(ZwQueryValueKey(KeyHandle, &ValNamePid, KeyValuePartialInformation, pidBuffer, sizeof(pidBuffer), &resultLength))) {
                ClientPID = (HANDLE)(ULONG_PTR)(*(PDWORD)(((PKEY_VALUE_PARTIAL_INFORMATION)pidBuffer)->Data));
            }

            // Query BufferAddress
            UNICODE_STRING ValNameAddr;
            RtlInitUnicodeString(&ValNameAddr, L"BufferAddress");
            UCHAR addrBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG64)];
            if (NT_SUCCESS(ZwQueryValueKey(KeyHandle, &ValNameAddr, KeyValuePartialInformation, addrBuffer, sizeof(addrBuffer), &resultLength))) {
                UmAddress = (PVOID)(*(PULONG64)(((PKEY_VALUE_PARTIAL_INFORMATION)addrBuffer)->Data));
            }

            // Delete the registry key immediately to hide traces
            ZwDeleteKey(KeyHandle);
            ZwClose(KeyHandle);

            if (ClientPID != NULL && UmAddress != NULL) {
                break; // Handshake successful!
            }
        }
        
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    DbgPrint("[PagingHook] Found UM Client! PID: %p, Addr: %p\n", ClientPID, UmAddress);

    // 2. Attach to the UM Process to map the memory
    PEPROCESS ClientProcess;
    if (NT_SUCCESS(PsLookupProcessByProcessId(ClientPID, &ClientProcess))) {
        KAPC_STATE ApcState;
        KeStackAttachProcess(ClientProcess, &ApcState);

        // 3. Create an MDL and lock the User-Mode pages into physical memory
        PMDL Mdl = IoAllocateMdl(UmAddress, sizeof(COMM_DATA), FALSE, FALSE, NULL);
        if (Mdl) {
            __try {
                MmProbeAndLockPages(Mdl, UserMode, IoModifyAccess);
                // Get a safe Kernel-Mode pointer to the same physical memory
                g_SharedBuffer = (PCOMM_DATA)MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                IoFreeMdl(Mdl);
            }
        }
        KeUnstackDetachProcess(&ApcState);
        ObDereferenceObject(ClientProcess);
    }

    // 4. The Infinite Polling Loop (The actual bridge)
    if (g_SharedBuffer) {
        DbgPrint("[PagingHook] Shared memory mapped at %p. Bridge active!\n", g_SharedBuffer);
        while (TRUE) {
            if (g_SharedBuffer->Magic == 0xDEADBEEF) {
                // Command received! Process Vanguard bypass requests here.
                DbgPrint("[PagingHook] Received Command: %lu\n", g_SharedBuffer->Operation);
                
                // Acknowledge completion (0 = SUCCESS)
                g_SharedBuffer->Magic = 0; 
            }
            
            // Sleep briefly to prevent 100% CPU core usage
            LARGE_INTEGER waitTime;
            waitTime.QuadPart = -10000; // 1 millisecond
            KeDelayExecutionThread(KernelMode, FALSE, &waitTime);
        }
    } else {
        DbgPrint("[PagingHook] Failed to map shared memory.\n");
    }
}

/* ================================================================== */
/*  DriverUnload                                                      */
/* ================================================================== */

/**
 * Clean up all resources when the driver is unloaded.
 */
static VOID
PagingHookUnload (PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER (DriverObject);

    //
    // 1. Remove the inline hook first (restores original SwapContext).
    //
    RemoveSwapContextHook ();

    //
    // 2. Free the cloned PML4 page.
    //
    if (gClonedPml4Virtual != NULL) {
        MmFreeContiguousMemory (gClonedPml4Virtual);
        gClonedPml4Virtual = NULL;
        gClonedPml4Physical.QuadPart = 0;
    }

    DbgPrint ("[PagingHook] Driver unloaded.\n");
}

/* ================================================================== */
/*  DriverEntry                                                       */
/* ================================================================== */

/**
 * Refactored Entry Point for PIC Injection.
 * Instead of a standard DriverEntry, this logic assumes it has been
 * manually mapped or injected as a stub.
 */
NTSTATUS
InitializePagingHook (
    PVOID ImageBase
    )
{
    NTSTATUS Status;
    HANDLE hThread;

    UNREFERENCED_PARAMETER (ImageBase);

    DbgPrint ("[PagingHook] Initializing injected payload.\n");

    //
    // Setup stealthy communication via System Thread
    //
    PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, SharedMemoryThread, NULL);
    ZwClose(hThread);

    /* ------------------------------------------------------------ */
    /*  Vanguard Shadow PML4 Logic (Academic Implementation)        */
    /* ------------------------------------------------------------ */
    // In a live bypass, you would use the SwapContext hook to identify
    // when the system is switching to a game thread. Instead of 
    // isolating thread 1234, you would capture the current CR3, 
    // identify if it's a Shadow PML4, and propagate its entries
    // back to your own communication mapping.
    /* ------------------------------------------------------------ */

    //
    // Install the SwapContext inline hook.
    // We call the installer but ignore the return status for now to ensure 
    // the driver stays loaded in the kernel for academic observation.
    //
      // TEMPORARILY DISABLED to prevent HVCI/VBS Secure Kernel crashes
    // and race conditions on multi-core systems.
    /*
    Status = InstallSwapContextHook ();
    if (!NT_SUCCESS (Status)) {
        DbgPrint ("[PagingHook] Hook installation failed: 0x%08X\n", Status);
    }
    */

    return STATUS_SUCCESS;
}

/**
 * Standard DriverEntry wrapper for testing as a .sys file.
 */
NTSTATUS
DriverEntry (
    PDRIVER_OBJECT  DriverObject,
    PUNICODE_STRING RegistryPath
    )
{
    UNREFERENCED_PARAMETER (DriverObject);
    UNREFERENCED_PARAMETER (RegistryPath);
    return InitializePagingHook((PVOID)0); // Passing 0 for testing purposes
}
