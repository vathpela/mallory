// SPDX-License-Identifier: BSD-2-Clause-Patent

/*
 * shim - trivial UEFI first-stage bootloader
 *
 * Copyright Red Hat, Inc
 * Author: Matthew Garrett
 *
 * Significant portions of this code are derived from Tianocore
 * (http://tianocore.sf.net) and are Copyright 2009-2012 Intel
 * Corporation.
 */

#include "shim.h"

#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/ocsp.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/dso.h>

#include <Library/BaseCryptLib.h>

#include <stdint.h>

#define OID_EKU_MODSIGN "1.3.6.1.4.1.2312.16.1.2"

extern struct cert_table cert_table;

static EFI_SYSTEM_TABLE *systab;
static EFI_HANDLE global_image_handle;
static EFI_LOADED_IMAGE *shim_li;
static EFI_LOADED_IMAGE shim_li_bak;

list_t sbat_var;

/*
 * Check whether we're in Secure Boot and user mode
 */
BOOLEAN secure_mode (void)
{
	static int first = 1;
	if (user_insecure_mode)
		return FALSE;

	if (variable_is_secureboot() != 1) {
		if (verbose && !in_protocol && first) {
			CHAR16 *title = L"Secure boot not enabled";
			CHAR16 *message = L"Press any key to continue";
			console_countdown(title, message, 5);
		}
		first = 0;
		return FALSE;
	}

	/* If we /do/ have "SecureBoot", but /don't/ have "SetupMode",
	 * then the implementation is bad, but we assume that secure boot is
	 * enabled according to the status of "SecureBoot".  If we have both
	 * of them, then "SetupMode" may tell us additional data, and we need
	 * to consider it.
	 */
	if (variable_is_setupmode(0) == 1) {
		if (verbose && !in_protocol && first) {
			CHAR16 *title = L"Platform is in setup mode";
			CHAR16 *message = L"Press any key to continue";
			console_countdown(title, message, 5);
		}
		first = 0;
		return FALSE;
	}

	first = 0;
	return TRUE;
}

static int
is_removable_media_path(EFI_LOADED_IMAGE *li)
{
	unsigned int pathlen = 0;
	CHAR16 *bootpath = NULL;
	int ret = 0;

	bootpath = DevicePathToStr(li->FilePath);

	/* Check the beginning of the string and the end, to avoid
	 * caring about which arch this is. */
	/* I really don't know why, but sometimes bootpath gives us
	 * L"\\EFI\\BOOT\\/BOOTX64.EFI".  So just handle that here...
	 */
	if (StrnCaseCmp(bootpath, L"\\EFI\\BOOT\\BOOT", 14) &&
			StrnCaseCmp(bootpath, L"\\EFI\\BOOT\\/BOOT", 15) &&
			StrnCaseCmp(bootpath, L"EFI\\BOOT\\BOOT", 13) &&
			StrnCaseCmp(bootpath, L"EFI\\BOOT\\/BOOT", 14))
		goto error;

	pathlen = StrLen(bootpath);
	if (pathlen < 5 || StrCaseCmp(bootpath + pathlen - 4, L".EFI"))
		goto error;

	ret = 1;

error:
	if (bootpath)
		FreePool(bootpath);

	return ret;
}

static int
should_use_fallback(EFI_HANDLE image_handle)
{
	EFI_LOADED_IMAGE *li;
	EFI_FILE_IO_INTERFACE *fio = NULL;
	EFI_FILE *vh = NULL;
	EFI_FILE *fh = NULL;
	EFI_STATUS efi_status;
	int ret = 0;

	efi_status = BS->HandleProtocol(image_handle, &EFI_LOADED_IMAGE_GUID,
	                                (void **)&li);
	if (EFI_ERROR(efi_status)) {
		perror(L"Could not get image for boot" EFI_ARCH L".efi: %r\n",
		       efi_status);
		return 0;
	}

	if (!is_removable_media_path(li))
		goto error;

	efi_status = BS->HandleProtocol(li->DeviceHandle, &FileSystemProtocol,
					(void **) &fio);
	if (EFI_ERROR(efi_status)) {
		perror(L"Could not get fio for li->DeviceHandle: %r\n",
		       efi_status);
		goto error;
	}

	efi_status = fio->OpenVolume(fio, &vh);
	if (EFI_ERROR(efi_status)) {
		perror(L"Could not open fio volume: %r\n", efi_status);
		goto error;
	}

	efi_status = vh->Open(vh, &fh, L"\\EFI\\BOOT" FALLBACK,
			      EFI_FILE_MODE_READ, 0);
	if (EFI_ERROR(efi_status)) {
		/* Do not print the error here - this is an acceptable case
		 * for removable media, where we genuinely don't want
		 * fallback.efi to exist.
		 * Print(L"Could not open \"\\EFI\\BOOT%s\": %r\n", FALLBACK,
		 *       efi_status);
		 */
		goto error;
	}

	ret = 1;
error:
	if (fh)
		fh->Close(fh);
	if (vh)
		vh->Close(vh);

	return ret;
}
/*
 * Open the second stage bootloader and read it into a buffer
 */
static EFI_STATUS load_image (EFI_LOADED_IMAGE *li, void **data,
			      int *datasize, CHAR16 *PathName)
{
	EFI_STATUS efi_status;
	EFI_HANDLE device;
	EFI_FILE_INFO *fileinfo = NULL;
	EFI_FILE_IO_INTERFACE *drive;
	EFI_FILE *root, *grub;
	UINTN buffersize = sizeof(EFI_FILE_INFO);

	device = li->DeviceHandle;

	dprint(L"attempting to load %s\n", PathName);
	/*
	 * Open the device
	 */
	efi_status = BS->HandleProtocol(device, &EFI_SIMPLE_FILE_SYSTEM_GUID,
					(void **) &drive);
	if (EFI_ERROR(efi_status)) {
		perror(L"Failed to find fs: %r\n", efi_status);
		goto error;
	}

	efi_status = drive->OpenVolume(drive, &root);
	if (EFI_ERROR(efi_status)) {
		perror(L"Failed to open fs: %r\n", efi_status);
		goto error;
	}

	/*
	 * And then open the file
	 */
	efi_status = root->Open(root, &grub, PathName, EFI_FILE_MODE_READ, 0);
	if (EFI_ERROR(efi_status)) {
		perror(L"Failed to open %s - %r\n", PathName, efi_status);
		goto error;
	}

	fileinfo = AllocatePool(buffersize);

	if (!fileinfo) {
		perror(L"Unable to allocate file info buffer\n");
		efi_status = EFI_OUT_OF_RESOURCES;
		goto error;
	}

	/*
	 * Find out how big the file is in order to allocate the storage
	 * buffer
	 */
	efi_status = grub->GetInfo(grub, &EFI_FILE_INFO_GUID, &buffersize,
				   fileinfo);
	if (efi_status == EFI_BUFFER_TOO_SMALL) {
		FreePool(fileinfo);
		fileinfo = AllocatePool(buffersize);
		if (!fileinfo) {
			perror(L"Unable to allocate file info buffer\n");
			efi_status = EFI_OUT_OF_RESOURCES;
			goto error;
		}
		efi_status = grub->GetInfo(grub, &EFI_FILE_INFO_GUID,
					   &buffersize, fileinfo);
	}

	if (EFI_ERROR(efi_status)) {
		perror(L"Unable to get file info: %r\n", efi_status);
		goto error;
	}

	buffersize = fileinfo->FileSize;
	*data = AllocatePool(buffersize);
	if (!*data) {
		perror(L"Unable to allocate file buffer\n");
		efi_status = EFI_OUT_OF_RESOURCES;
		goto error;
	}

	/*
	 * Perform the actual read
	 */
	efi_status = grub->Read(grub, &buffersize, *data);
	if (efi_status == EFI_BUFFER_TOO_SMALL) {
		FreePool(*data);
		*data = AllocatePool(buffersize);
		efi_status = grub->Read(grub, &buffersize, *data);
	}
	if (EFI_ERROR(efi_status)) {
		perror(L"Unexpected return from initial read: %r, buffersize %x\n",
		       efi_status, buffersize);
		goto error;
	}

	*datasize = buffersize;

	FreePool(fileinfo);

	return EFI_SUCCESS;
error:
	if (*data) {
		FreePool(*data);
		*data = NULL;
	}

	if (fileinfo)
		FreePool(fileinfo);
	return efi_status;
}

VOID
restore_loaded_image(VOID)
{
	if (shim_li->FilePath)
		FreePool(shim_li->FilePath);

	/*
	 * Restore our original loaded image values
	 */
	CopyMem(shim_li, &shim_li_bak, sizeof(shim_li_bak));
}

/*
 * Load and run an EFI executable
 */
EFI_STATUS read_image(EFI_HANDLE image_handle, CHAR16 *ImagePath,
		      CHAR16 **PathName, void **data, int *datasize)
{
	EFI_STATUS efi_status;
	void *sourcebuffer = NULL;
	UINT64 sourcesize = 0;

	/*
	 * We need to refer to the loaded image protocol on the running
	 * binary in order to find our path
	 */
	efi_status = BS->HandleProtocol(image_handle, &EFI_LOADED_IMAGE_GUID,
					(void **)&shim_li);
	if (EFI_ERROR(efi_status)) {
		perror(L"Unable to init protocol\n");
		return efi_status;
	}

	/*
	 * Build a new path from the existing one plus the executable name
	 */
	efi_status = generate_path_from_image_path(shim_li, ImagePath, PathName);
	if (EFI_ERROR(efi_status)) {
		perror(L"Unable to generate path %s: %r\n", ImagePath,
		       efi_status);
		return efi_status;
	}

	if (findNetboot(shim_li->DeviceHandle)) {
		efi_status = parseNetbootinfo(image_handle);
		if (EFI_ERROR(efi_status)) {
			perror(L"Netboot parsing failed: %r\n", efi_status);
			return EFI_PROTOCOL_ERROR;
		}
		efi_status = FetchNetbootimage(image_handle, &sourcebuffer,
					       &sourcesize);
		if (EFI_ERROR(efi_status)) {
			perror(L"Unable to fetch TFTP image: %r\n",
			       efi_status);
			return efi_status;
		}
		*data = sourcebuffer;
		*datasize = sourcesize;
	} else if (find_httpboot(shim_li->DeviceHandle)) {
		efi_status = httpboot_fetch_buffer (image_handle,
						    &sourcebuffer,
						    &sourcesize);
		if (EFI_ERROR(efi_status)) {
			perror(L"Unable to fetch HTTP image: %r\n",
			       efi_status);
			return efi_status;
		}
		*data = sourcebuffer;
		*datasize = sourcesize;
	} else {
		/*
		 * Read the new executable off disk
		 */
		efi_status = load_image(shim_li, data, datasize, *PathName);
		if (EFI_ERROR(efi_status)) {
			perror(L"Failed to load image %s: %r\n",
			       PathName, efi_status);
			PrintErrors();
			ClearErrors();
			return efi_status;
		}
	}

	if (*datasize < 0)
		efi_status = EFI_INVALID_PARAMETER;

	return efi_status;
}

/*
 * Load and run an EFI executable
 */
EFI_STATUS start_image(EFI_HANDLE image_handle, CHAR16 *ImagePath)
{
	EFI_STATUS efi_status;
	EFI_IMAGE_ENTRY_POINT entry_point;
	EFI_PHYSICAL_ADDRESS alloc_address;
	UINTN alloc_pages;
	CHAR16 *PathName = NULL;
	void *data = NULL;
	int datasize = 0;

	efi_status = read_image(image_handle, ImagePath, &PathName, &data,
				&datasize);
	if (EFI_ERROR(efi_status))
		goto done;

	/*
	 * We need to modify the loaded image protocol entry before running
	 * the new binary, so back it up
	 */
	CopyMem(&shim_li_bak, shim_li, sizeof(shim_li_bak));

	/*
	 * Update the loaded image with the second stage loader file path
	 */
	shim_li->FilePath = FileDevicePath(NULL, PathName);
	if (!shim_li->FilePath) {
		perror(L"Unable to update loaded image file path\n");
		efi_status = EFI_OUT_OF_RESOURCES;
		goto restore;
	}

	/*
	 * Verify and, if appropriate, relocate and execute the executable
	 */
	efi_status = handle_image(data, datasize, shim_li, &entry_point,
				  &alloc_address, &alloc_pages);
	if (EFI_ERROR(efi_status)) {
		perror(L"Failed to load image: %r\n", efi_status);
		PrintErrors();
		ClearErrors();
		goto restore;
	}

	loader_is_participating = 0;

	/*
	 * The binary is trusted and relocated. Run it
	 */
	efi_status = entry_point(image_handle, systab);

restore:
	restore_loaded_image();
done:
	if (PathName)
		FreePool(PathName);

	if (data)
		FreePool(data);

	return efi_status;
}

/*
 * Load and run grub. If that fails because grub isn't trusted, load and
 * run MokManager.
 */
EFI_STATUS init_grub(EFI_HANDLE image_handle)
{
	EFI_STATUS efi_status;
	int use_fb = should_use_fallback(image_handle);

	if (use_fb) {
		efi_status = fallback(image_handle);
	} else {
		efi_status = start_image(image_handle, second_stage);
		if (efi_status == EFI_SECURITY_VIOLATION ||
		    efi_status == EFI_ACCESS_DENIED) {
			efi_status = mok_manager();
			if (EFI_ERROR(efi_status)) {
				console_print(L"mok_manager returned %r\n", efi_status);
				msleep(2000000);
				return efi_status;
			}

			efi_status = start_image(image_handle, second_stage);
		}
	}

	// If the filename is invalid, or the file does not exist,
	// just fallback to the default loader.
	if (!use_fb && (efi_status == EFI_INVALID_PARAMETER ||
	                efi_status == EFI_NOT_FOUND)) {
		console_print(
			L"start_image() returned %r, falling back to default loader\n",
			efi_status);
		msleep(2000000);
		load_options = NULL;
		load_options_size = 0;
		efi_status = start_image(image_handle, DEFAULT_LOADER);
	}

	if (EFI_ERROR(efi_status)) {
		console_print(L"start_image() returned %r\n", efi_status);
		msleep(2000000);
	}

	return efi_status;
}

/*
 * Check the load options to specify the second stage loader
 */
EFI_STATUS set_second_stage (EFI_HANDLE image_handle)
{
	EFI_STATUS efi_status;
	EFI_LOADED_IMAGE *li = NULL;

	second_stage = DEFAULT_LOADER;
	load_options = NULL;
	load_options_size = 0;

	efi_status = BS->HandleProtocol(image_handle, &LoadedImageProtocol,
					(void **) &li);
	if (EFI_ERROR(efi_status)) {
		perror (L"Failed to get load options: %r\n", efi_status);
		return efi_status;
	}

#if defined(DISABLE_REMOVABLE_LOAD_OPTIONS)
	/*
	 * boot services build very strange load options, and we might misparse them,
	 * causing boot failures on removable media.
	 */
	if (is_removable_media_path(li)) {
		dprint("Invoked from removable media path, ignoring boot options");
		return EFI_SUCCESS;
	}
#endif

	efi_status = parse_load_options(li);
	if (EFI_ERROR(efi_status)) {
		perror (L"Failed to get load options: %r\n", efi_status);
		return efi_status;
	}

	return EFI_SUCCESS;
}

EFI_STATUS
install_shim_protocols(void)
{
	EFI_STATUS efi_status;

#if defined(OVERRIDE_SECURITY_POLICY)
	/*
	 * Install the security protocol hook
	 */
	security_policy_install(shim_verify);
#endif

	efi_status = install_protocol_v1();
	return efi_status;
}

void
uninstall_shim_protocols(void)
{
	unregister_protocol_v1();

#if defined(OVERRIDE_SECURITY_POLICY)
	/*
	 * Clean up the security protocol hook
	 */
	security_policy_uninstall();
#endif
}

EFI_STATUS
load_cert_file(EFI_HANDLE image_handle, CHAR16 *filename, CHAR16 *PathName)
{
	EFI_STATUS efi_status;
	EFI_LOADED_IMAGE li;
	PE_COFF_LOADER_IMAGE_CONTEXT context;
	EFI_IMAGE_SECTION_HEADER *Section;
	EFI_SIGNATURE_LIST *certlist;
	void *pointer;
	UINT32 original;
	int datasize = 0;
	void *data = NULL;
	int i;

	efi_status = read_image(image_handle, filename, &PathName,
				&data, &datasize);
	if (EFI_ERROR(efi_status))
		return efi_status;

	memset(&li, 0, sizeof(li));
	memcpy(&li.FilePath[0], filename, MIN(StrSize(filename), sizeof(li.FilePath)));

	efi_status = verify_image(data, datasize, &li, &context);
	if (EFI_ERROR(efi_status))
		return efi_status;

	Section = context.FirstSection;
	for (i = 0; i < context.NumberOfSections; i++, Section++) {
		if (CompareMem(Section->Name, ".db\0\0\0\0\0", 8) == 0) {
			original = user_cert_size;
			if (Section->SizeOfRawData < sizeof(EFI_SIGNATURE_LIST)) {
				continue;
			}
			pointer = ImageAddress(data, datasize,
					       Section->PointerToRawData);
			if (!pointer) {
				continue;
			}
			certlist = pointer;
			user_cert_size += certlist->SignatureListSize;;
			user_cert = ReallocatePool(user_cert, original,
						   user_cert_size);
			memcpy(user_cert + original, pointer,
			       certlist->SignatureListSize);
		}
	}
	FreePool(data);
	return EFI_SUCCESS;
}

/* Read additional certificates from files (after verifying signatures) */
EFI_STATUS
load_certs(EFI_HANDLE image_handle)
{
	EFI_STATUS efi_status;
	EFI_LOADED_IMAGE *li = NULL;
	CHAR16 *PathName = NULL;
	EFI_FILE *root, *dir;
	EFI_FILE_INFO *info;
	EFI_HANDLE device;
	EFI_FILE_IO_INTERFACE *drive;
	UINTN buffersize = 0;
	void *buffer = NULL;

	efi_status = gBS->HandleProtocol(image_handle, &EFI_LOADED_IMAGE_GUID,
					 (void **)&li);
	if (EFI_ERROR(efi_status)) {
		perror(L"Unable to init protocol\n");
		return efi_status;
	}

	efi_status = generate_path_from_image_path(li, L"", &PathName);
	if (EFI_ERROR(efi_status))
		goto done;

	device = li->DeviceHandle;
	efi_status = gBS->HandleProtocol(device, &EFI_SIMPLE_FILE_SYSTEM_GUID,
					 (void **)&drive);
	if (EFI_ERROR(efi_status)) {
		perror(L"Failed to find fs: %r\n", efi_status);
		goto done;
	}

	efi_status = drive->OpenVolume(drive, &root);
	if (EFI_ERROR(efi_status)) {
		perror(L"Failed to open fs: %r\n", efi_status);
		goto done;
	}

	efi_status = root->Open(root, &dir, PathName, EFI_FILE_MODE_READ, 0);
	if (EFI_ERROR(efi_status)) {
		perror(L"Failed to open %s - %r\n", PathName, efi_status);
		goto done;
	}

	while (1) {
		int old = buffersize;
		efi_status = dir->Read(dir, &buffersize, buffer);
		if (efi_status == EFI_BUFFER_TOO_SMALL) {
			buffer = ReallocatePool(buffer, old, buffersize);
			continue;
		} else if (EFI_ERROR(efi_status)) {
			perror(L"Failed to read directory %s - %r\n", PathName,
			       efi_status);
			goto done;
		}

		info = (EFI_FILE_INFO *)buffer;
		if (buffersize == 0 || !info)
			goto done;

		if (StrnCaseCmp(info->FileName, L"shim_certificate", 16) == 0) {
			load_cert_file(image_handle, info->FileName, PathName);
		}
	}
done:
	FreePool(buffer);
	FreePool(PathName);
	return efi_status;
}

EFI_STATUS
shim_init(void)
{
	EFI_STATUS efi_status;

	dprint(L"%a", shim_version);

	/* Set the second stage loader */
	efi_status = set_second_stage(global_image_handle);
	if (EFI_ERROR(efi_status)) {
		perror(L"set_second_stage() failed: %r\n", efi_status);
		return efi_status;
	}

	if (secure_mode()) {
		if (vendor_authorized_size || vendor_deauthorized_size) {
			/*
			 * If shim includes its own certificates then ensure
			 * that anything it boots has performed some
			 * validation of the next image.
			 */
			hook_system_services(systab);
			loader_is_participating = 0;
		}

	}

	hook_exit(systab);

	efi_status = install_shim_protocols();
	if (EFI_ERROR(efi_status))
		perror(L"install_shim_protocols() failed: %r\n", efi_status);

	return efi_status;
}

void
shim_fini(void)
{
	if (secure_mode())
		cleanup_sbat_var(&sbat_var);

	/*
	 * Remove our protocols
	 */
	uninstall_shim_protocols();

	if (secure_mode()) {

		/*
		 * Remove our hooks from system services.
		 */
		unhook_system_services();
	}

	unhook_exit();

	console_fini();
}

extern EFI_STATUS
efi_main(EFI_HANDLE passed_image_handle, EFI_SYSTEM_TABLE *passed_systab);

static void
__attribute__((__optimize__("0")))
debug_hook(void)
{
	UINT8 *data = NULL;
	UINTN dataSize = 0;
	EFI_STATUS efi_status;
	register volatile UINTN x = 0;
	extern char _text, _data;

	if (x)
		return;

	efi_status = get_variable(DEBUG_VAR_NAME, &data, &dataSize,
				  SHIM_LOCK_GUID);
	if (EFI_ERROR(efi_status)) {
		return;
	}

	FreePool(data);

	console_print(L"add-symbol-file "DEBUGDIR
		      L"shim" EFI_ARCH L".efi.debug 0x%08x -s .data 0x%08x\n",
		      &_text, &_data);

	console_print(L"Pausing for debugger attachment.\n");
	console_print(L"To disable this, remove the EFI variable %s-%g .\n",
		      DEBUG_VAR_NAME, &SHIM_LOCK_GUID);
	x = 1;
	while (x++) {
		/* Make this so it can't /totally/ DoS us. */
#if defined(__x86_64__) || defined(__i386__) || defined(__i686__)
		if (x > 4294967294ULL)
			break;
#elif defined(__aarch64__)
		if (x > 1000)
			break;
#else
		if (x > 12000)
			break;
#endif
		wait_for_debug();
	}
	x = 1;
}

void
devel_egress(devel_egress_action action UNUSED)
{
#ifdef ENABLE_SHIM_DEVEL
	char *reasons[] = {
		[COLD_RESET] = "reset",
		[EXIT_FAILURE] = "exit",
	};
	if (action == EXIT_SUCCESS)
		return;

	console_print(L"Waiting to %a...", reasons[action]);
	for (size_t sleepcount = 0; sleepcount < 10; sleepcount++) {
		console_print(L"%d...", 10 - sleepcount);
		msleep(1000000);
	}
	console_print(L"\ndoing %a\n", action);

	if (action == COLD_RESET)
		RT->ResetSystem(EfiResetCold, EFI_SECURITY_VIOLATION, 0, NULL);
#endif
}

EFI_STATUS
efi_main (EFI_HANDLE passed_image_handle, EFI_SYSTEM_TABLE *passed_systab)
{
	EFI_STATUS efi_status;
	EFI_HANDLE image_handle;

	verification_method = VERIFIED_BY_NOTHING;

	vendor_authorized_size = cert_table.vendor_authorized_size;
	vendor_authorized = (UINT8 *)&cert_table + cert_table.vendor_authorized_offset;

	vendor_deauthorized_size = cert_table.vendor_deauthorized_size;
	vendor_deauthorized = (UINT8 *)&cert_table + cert_table.vendor_deauthorized_offset;

	CHAR16 *msgs[] = {
		L"import_mok_state() failed",
		L"shim_init() failed",
		L"import of SBAT data failed",
		L"SBAT self-check failed",
		SBAT_VAR_NAME L" UEFI variable setting failed",
		NULL
	};
	enum {
		IMPORT_MOK_STATE,
		SHIM_INIT,
		IMPORT_SBAT,
		SBAT_SELF_CHECK,
		SET_SBAT,
	} msg = IMPORT_MOK_STATE;

	systab = passed_systab;
	image_handle = global_image_handle = passed_image_handle;

	/*
	 * Ensure that gnu-efi functions are available
	 */
	InitializeLib(image_handle, systab);
	setup_verbosity();

	dprint(L"vendor_authorized:0x%08lx vendor_authorized_size:%lu\n",
	       vendor_authorized, vendor_authorized_size);
	dprint(L"vendor_deauthorized:0x%08lx vendor_deauthorized_size:%lu\n",
	       vendor_deauthorized, vendor_deauthorized_size);

	/*
	 * if SHIM_DEBUG is set, wait for a debugger to attach.
	 */
	debug_hook();

	efi_status = set_sbat_uefi_variable();
	if (EFI_ERROR(efi_status) && secure_mode()) {
		perror(L"%s variable initialization failed\n", SBAT_VAR_NAME);
		msg = SET_SBAT;
		goto die;
	} else if (EFI_ERROR(efi_status)) {
		dprint(L"%s variable initialization failed: %r\n",
		       SBAT_VAR_NAME, efi_status);
	}

	if (secure_mode()) {
		char *sbat_start = (char *)&_sbat;
		char *sbat_end = (char *)&_esbat;

		INIT_LIST_HEAD(&sbat_var);
		efi_status = parse_sbat_var(&sbat_var);
		if (EFI_ERROR(efi_status)) {
			perror(L"Parsing %s variable failed: %r\n",
				SBAT_VAR_NAME, efi_status);
			msg = IMPORT_SBAT;
			goto die;
		}

		efi_status = verify_sbat_section(sbat_start, sbat_end - sbat_start - 1);
		if (EFI_ERROR(efi_status)) {
			perror(L"Verifiying shim SBAT data failed: %r\n",
			       efi_status);
			msg = SBAT_SELF_CHECK;
			goto die;
		}
		dprint(L"SBAT self-check succeeded\n");
	}

	init_openssl();

	if (secure_mode()) {
		efi_status = load_certs(global_image_handle);
		if (EFI_ERROR(efi_status)) {
			LogError(L"Failed to load addon certificates\n");
		}
	}

	/*
	 * Before we do anything else, validate our non-volatile,
	 * boot-services-only state variables are what we think they are.
	 */
	efi_status = import_mok_state(image_handle);
	if (!secure_mode() &&
	    (efi_status == EFI_INVALID_PARAMETER ||
	     efi_status == EFI_OUT_OF_RESOURCES)) {
		/*
		 * Make copy failures fatal only if secure_mode is enabled, or
		 * the error was anything else than EFI_INVALID_PARAMETER or
		 * EFI_OUT_OF_RESOURCES.
		 * There are non-secureboot firmware implementations that don't
		 * reserve enough EFI variable memory to fit the variable.
		 */
		console_print(L"Importing MOK states has failed: %s: %r\n",
			      msgs[msg], efi_status);
		console_print(L"Continuing boot since secure mode is disabled");
	} else if (EFI_ERROR(efi_status)) {
die:
		console_print(L"Something has gone seriously wrong: %s: %r\n",
			      msgs[msg], efi_status);
#if defined(ENABLE_SHIM_DEVEL)
		devel_egress(COLD_RESET);
#else
		msleep(5000000);
		RT->ResetSystem(EfiResetShutdown, EFI_SECURITY_VIOLATION,
				0, NULL);
#endif
	}

	efi_status = shim_init();
	if (EFI_ERROR(efi_status)) {
		msg = SHIM_INIT;
		goto die;
	}

	/*
	 * Tell the user that we're in insecure mode if necessary
	 */
	if (user_insecure_mode) {
		console_print(L"Booting in insecure mode\n");
		msleep(2000000);
	}

	/*
	 * Hand over control to the second stage bootloader
	 */
	efi_status = init_grub(image_handle);

	shim_fini();
	devel_egress(EFI_ERROR(efi_status) ? EXIT_FAILURE : EXIT_SUCCESS);
	return efi_status;
}
