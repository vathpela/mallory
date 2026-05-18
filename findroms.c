// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * findroms.c - find some roms, boyo
 * Copyright Peter Jones <pjones@redhat.com>
 */

#include "shim.h"

#pragma GCC diagnostic ignored "-Wunused-parameter"

EFI_STATUS
efi_main (EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *systab)
{
	static EFI_GUID pci_guid = EFI_PCI_IO_PROTOCOL_GUID;
	EFI_STATUS efi_status;
	UINTN nhandles = 0, i;
	EFI_HANDLE *handles = NULL;

	InitializeLib(image_handle, systab);

	verbose = 1;
	efi_status = BS->LocateHandleBuffer(ByProtocol, &pci_guid, NULL,
					    &nhandles, &handles);
	if (EFI_ERROR(efi_status)) {
		perror(L"Unable to find pci protocol handles\n");
		BS->Stall(5000000);
		return EFI_SUCCESS;
	}

	console_print(L"\n");
	for (i = 0; i < nhandles; i++) {
		EFI_PCI_IO_PROTOCOL *pci = NULL;
		UINTN segment_number = 0;
		UINTN bus_number = 0;
		UINTN device_number = 0;
		UINTN function_number = 0;

		efi_status = BS->HandleProtocol(handles[i], &pci_guid,
						(void **)&pci);
		if (EFI_ERROR(efi_status)) {
			perror(L"Unable to find pci protocol for handle %u (%p)\n", i, handles[i]);
			BS->Stall(5000000);
			return EFI_SUCCESS;
		}

		if (!pci->RomImage || !pci->RomSize)
			continue;

		efi_status = pci->GetLocation(pci, &segment_number, &bus_number,
					      &device_number, &function_number);
		if (EFI_ERROR(efi_status)) {
			dprint(L"Option ROM at 0x%llx size %u\n", pci->RomImage, pci->RomSize);
			dhexdump(pci->RomImage, MIN(pci->RomSize, 4096));
			continue;
		}
		dprint(L"Option ROM at 0x%llx size %u for device %04x:%02x:%02x.%u\n",
		       pci->RomImage, pci->RomSize, segment_number, bus_number,
		       device_number, function_number);
		dhexdump(pci->RomImage, MIN(pci->RomSize, 4096));
	}

	BS->Stall(5000000);
	return EFI_SUCCESS;
}

// vim:fenc=utf-8:tw=75:noet
