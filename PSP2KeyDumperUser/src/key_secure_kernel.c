/*
 * PSP2KeyDumper
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2/kernel/clib.h>
#include "psp2keydumper.h"
#include "key.h"
#include "slb2.h"

char kernel_buffer[0xC000] __attribute__((aligned(0x40)));

int extract_secure_kernel_360_key(SceSlb2Context *pSlb2Ctx){

	int res;
	SceSize kernel_buffer_size = sizeof(kernel_buffer);

	res = decrypt_enc(pSlb2Ctx, "secure_kernel.enc", kernel_buffer, &kernel_buffer_size);
	if(res < 0){
		sceClibPrintf("decrypt_enc failed : 0x%X\n", res);
		return res;
	}

	void *secure_kernel_bin = kernel_buffer + 0x2C0;

	if(sceClibStrncmp(secure_kernel_bin + 0x7C50, "Congratulations!", 0x10) != 0){
		sceClibPrintf("%s:Enc could not be decrypted correctly.\n", __FUNCTION__);
		return -1;
	}

	keyRegister("secure_kernel_ver2", "prog_rvk_rsa_e", secure_kernel_bin + 0x7C44, 0x4);
	keyRegister("secure_kernel_ver2", "prog_rvk_rsa_n", secure_kernel_bin + 0x7B40, 0x100);
	keyRegister("secure_kernel_ver2", "prog_rvk_iv",    secure_kernel_bin + 0x7B30, 0x10);
	keyRegister("secure_kernel_ver2", "prog_rvk_key",   secure_kernel_bin + 0x7B10, 0x20);

	keyRegister("secure_kernel_ver2", "security_module_rsa_e", secure_kernel_bin + 0x7B08, 0x4);
	keyRegister("secure_kernel_ver2", "security_module_rsa_n", secure_kernel_bin + 0x7A04, 0x100);
	keyRegister("secure_kernel_ver2", "security_module_iv",    secure_kernel_bin + 0x79F4, 0x10);
	keyRegister("secure_kernel_ver2", "security_module_key",   secure_kernel_bin + 0x79D4, 0x20);

	keyRegister("secure_kernel_ver2", "unknown_key_0x79C4", secure_kernel_bin + 0x79C4, 0x10);

	return 0;
}
