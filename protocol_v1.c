// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * protocol_v1.c - the shim protocol v1
 * Copyright Peter Jones <pjones@redhat.com>
 */

#include "shim.h"

/*
 * Check that the binary is permitted to load by SBAT.
 */
EFI_STATUS
verify_buffer_sbat (char *data, int datasize,
		    PE_COFF_LOADER_IMAGE_CONTEXT *context)
{
	int i;
	EFI_IMAGE_SECTION_HEADER *Section;
	char *SBATBase = NULL;
	size_t SBATSize = 0;

	Section = context->FirstSection;
	for (i = 0; i < context->NumberOfSections; i++, Section++) {
		if (CompareMem(Section->Name, ".sbat\0\0\0", 8) != 0)
			continue;

		if (SBATBase || SBATSize) {
			perror(L"Image has multiple SBAT sections\n");
			return EFI_UNSUPPORTED;
		}

		if (Section->NumberOfRelocations != 0 ||
		    Section->PointerToRelocations != 0) {
			perror(L"SBAT section has relocations\n");
			return EFI_UNSUPPORTED;
		}

		/* The virtual size corresponds to the size of the SBAT
		 * metadata and isn't necessarily a multiple of the file
		 * alignment. The on-disk size is a multiple of the file
		 * alignment and is zero padded. Make sure that the
		 * on-disk size is at least as large as virtual size,
		 * and ignore the section if it isn't. */
		if (Section->SizeOfRawData &&
		    Section->SizeOfRawData >= Section->Misc.VirtualSize) {
			SBATBase = ImageAddress(data, datasize,
						Section->PointerToRawData);
			SBATSize = Section->SizeOfRawData;
			dprint(L"sbat section base:0x%lx size:0x%lx\n",
			       SBATBase, SBATSize);
		}
	}

	return verify_sbat_section(SBATBase, SBATSize);
}

/*
 * Check that the signature is valid and matches the binary and that
 * the binary is permitted to load by SBAT.
 */
EFI_STATUS
verify_buffer (char *data, int datasize,
	       PE_COFF_LOADER_IMAGE_CONTEXT *context,
	       UINT8 *sha256hash, UINT8 *sha1hash)
{
	EFI_STATUS efi_status;

	efi_status = verify_buffer_sbat(data, datasize, context);
	if (EFI_ERROR(efi_status))
		return efi_status;

	return verify_buffer_authenticode(data, datasize, context, sha256hash, sha1hash);
}

/*
 * Protocol entry point. If secure boot is enabled, verify that the provided
 * buffer is signed with a trusted key.
 */
EFI_STATUS shim_verify (void *buffer, UINT32 size)
{
	EFI_STATUS efi_status = EFI_SUCCESS;
	PE_COFF_LOADER_IMAGE_CONTEXT context;
	UINT8 sha1hash[SHA1_DIGEST_SIZE];
	UINT8 sha256hash[SHA256_DIGEST_SIZE];

	if ((INT32)size < 0)
		return EFI_INVALID_PARAMETER;

	loader_is_participating = 1;
	in_protocol = 1;

	efi_status = read_header(buffer, size, &context);
	if (EFI_ERROR(efi_status))
		goto done;

	efi_status = generate_hash(buffer, size, &context,
				   sha256hash, sha1hash);
	if (EFI_ERROR(efi_status))
		goto done;

	/* Measure the binary into the TPM */
#ifdef REQUIRE_TPM
	efi_status =
#endif
	tpm_log_pe((EFI_PHYSICAL_ADDRESS)(UINTN)buffer, size, 0, NULL,
		   sha1hash, 4);
#ifdef REQUIRE_TPM
	if (EFI_ERROR(efi_status))
		goto done;
#endif

	if (!secure_mode()) {
		efi_status = EFI_SUCCESS;
		goto done;
	}

	efi_status = verify_buffer(buffer, size,
				   &context, sha256hash, sha1hash);
done:
	in_protocol = 0;
	return efi_status;
}

static EFI_STATUS shim_hash (char *data, int datasize,
			     PE_COFF_LOADER_IMAGE_CONTEXT *context,
			     UINT8 *sha256hash, UINT8 *sha1hash)
{
	EFI_STATUS efi_status;

	if (datasize < 0)
		return EFI_INVALID_PARAMETER;

	in_protocol = 1;
	efi_status = generate_hash(data, datasize, context,
				   sha256hash, sha1hash);
	in_protocol = 0;

	return efi_status;
}

static EFI_STATUS shim_read_header(void *data, unsigned int datasize,
				   PE_COFF_LOADER_IMAGE_CONTEXT *context)
{
	EFI_STATUS efi_status;

	in_protocol = 1;
	efi_status = read_header(data, datasize, context);
	in_protocol = 0;

	return efi_status;
}

static SHIM_LOCK shim_lock_interface;
static EFI_HANDLE shim_lock_handle;

EFI_STATUS
install_protocol_v1(void)
{
	SHIM_LOCK *shim_lock;
	EFI_STATUS efi_status;

	/*
	 * Set up the shim lock protocol so that grub and MokManager can
	 * call back in and use shim functions
	 */
	shim_lock_interface.Verify = shim_verify;
	shim_lock_interface.Hash = shim_hash;
	shim_lock_interface.Context = shim_read_header;

	/*
	 * Did another instance of shim earlier already install the
	 * protocol? If so, get rid of it.
	 *
	 * We have to uninstall shim's protocol here, because if we're
	 * On the fallback.efi path, then our call pathway is:
	 *
	 * shim->fallback->shim->grub
	 * ^               ^      ^
	 * |               |      \- gets protocol #0
	 * |               \- installs its protocol (#1)
	 * \- installs its protocol (#0)
	 * and if we haven't removed this, then grub will get the *first*
	 * shim's protocol, but it'll get the second shim's systab
	 * replacements.  So even though it will participate and verify
	 * the kernel, the systab never finds out.
	 */
	efi_status = LibLocateProtocol(&SHIM_LOCK_GUID, (VOID **)&shim_lock);
	if (!EFI_ERROR(efi_status))
		uninstall_shim_protocols();

	/*
	 * Install the protocol
	 */
	efi_status = BS->InstallProtocolInterface(&shim_lock_handle,
						  &SHIM_LOCK_GUID,
						  EFI_NATIVE_INTERFACE,
						  &shim_lock_interface);
	if (EFI_ERROR(efi_status)) {
		console_error(L"Could not install security protocol",
			      efi_status);
		return efi_status;
	}

	if (!secure_mode())
		return EFI_SUCCESS;

#if defined(OVERRIDE_SECURITY_POLICY)
	/*
	 * Install the security protocol hook
	 */
	security_policy_install(shim_verify);
#endif
	return EFI_SUCCESS;
}

void
unregister_protocol_v1(void)
{
	/*
	 * If we're back here then clean everything up before exiting
	 */
	BS->UninstallProtocolInterface(shim_lock_handle, &SHIM_LOCK_GUID,
				       &shim_lock_interface);

	if (!secure_mode())
		return;

#if defined(OVERRIDE_SECURITY_POLICY)
	/*
	 * Clean up the security protocol hook
	 */
	security_policy_uninstall();
#endif
}

// vim:fenc=utf-8:tw=75:noet
