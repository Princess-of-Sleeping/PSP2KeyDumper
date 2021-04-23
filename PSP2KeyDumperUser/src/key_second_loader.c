/*
 * PSP2KeyDumper
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2/kernel/clib.h>
#include "psp2keydumper.h"
#include "key.h"
#include "slb2.h"

char loader_buffer[0x10000] __attribute__((aligned(0x40)));

int extract_second_loader_360_key(SceSlb2Context *pSlb2Ctx){

	int res;
	SceSize loader_buffer_size = sizeof(loader_buffer);

	res = decrypt_enc(pSlb2Ctx, "second_loader.enc", loader_buffer, &loader_buffer_size);
	if(res < 0){
		sceClibPrintf("decrypt_enc failed : 0x%X\n", res);
		return res;
	}

	void *second_loader_bin = loader_buffer + 0x2C0;

	if(sceClibStrncmp(loader_buffer + 0xC424, "Sony Computer Entertainment Inc.", 0x20) != 0){
		sceClibPrintf("%s:Enc could not be decrypted correctly.\n", __FUNCTION__);
		return -1;
	}

	// Just a copy of 0xC900
	if(0){
		keyRegister("second_loader", "snvs_proto_aes_cmac",      second_loader_bin + 0xC9D0, 0x20);
		keyRegister("second_loader", "snvs_proto_aes_xts_tweak", second_loader_bin + 0xC9B0, 0x20);
		keyRegister("second_loader", "snvs_proto_aes_xts_key",   second_loader_bin + 0xC990, 0x20);
	}

	keyRegister("second_loader", "snvs_proto_aes_xts_key2",  second_loader_bin + 0xC980, 0x10);

	keyRegister("second_loader", "snvs_proto_aes_cmac",      second_loader_bin + 0xC940, 0x20);
	keyRegister("second_loader", "snvs_proto_aes_xts_tweak", second_loader_bin + 0xC920, 0x20);
	keyRegister("second_loader", "snvs_proto_aes_xts_key",   second_loader_bin + 0xC900, 0x20);

	// same to secure_kernel_ver2->unknown_key_0x79C4
	keyRegister("second_loader_ver2", "unknown_key_0xC87C", second_loader_bin + 0xC87C, 0x10);

	keyRegister("second_loader_ver2", "kbl_rsa_e", second_loader_bin + 0xC804, 0x4);
	keyRegister("second_loader_ver2", "kbl_rsa_n", second_loader_bin + 0xC700, 0x100);
	keyRegister("second_loader_ver2", "kbl_iv",    second_loader_bin + 0xC6E0, 0x10);
	keyRegister("second_loader_ver2", "kbl_key",   second_loader_bin + 0xC6C0, 0x20);

	// 0xC4E0 -> maybe sha1 or ecdsa160
	keyRegister("second_loader_ver2", "syscon_data_0xC4D0", second_loader_bin + 0xC4D0, 0x10);
	keyRegister("second_loader_ver2", "syscon_data_0xC4C0", second_loader_bin + 0xC4C0, 0x10);
	keyRegister("second_loader_ver2", "syscon_data_0xC4B0", second_loader_bin + 0xC4B0, 0x10);
	keyRegister("second_loader_ver2", "syscon_data_0xC4A0", second_loader_bin + 0xC4A0, 0x10);
	keyRegister("second_loader_ver2", "syscon_data_0xC490", second_loader_bin + 0xC490, 0x10);
	keyRegister("second_loader_ver2", "syscon_data_0xC480", second_loader_bin + 0xC480, 0x10);
	keyRegister("second_loader_ver2", "syscon_data_0xC470", second_loader_bin + 0xC470, 0x10);
	keyRegister("second_loader_ver2", "syscon_data_0xC460", second_loader_bin + 0xC460, 0x10);
	keyRegister("second_loader_ver2", "syscon_data_0xC440", second_loader_bin + 0xC440, 0x10);

	keyRegister("second_loader", "idstorage_smi_rsa_n",    second_loader_bin + 0xC240, 0x100);

	keyRegister("second_loader", "idstorage_smi2_iv",      second_loader_bin + 0xC230, 0x10);
	keyRegister("second_loader", "idstorage_smi2_seed_iv", second_loader_bin + 0xC220, 0x10);
	keyRegister("second_loader", "idstorage_smi2_seed",    second_loader_bin + 0xC200, 0x20);

	keyRegister("second_loader", "idstorage_smi1_iv",      second_loader_bin + 0xC1F0, 0x10);
	keyRegister("second_loader", "idstorage_smi1_seed_iv", second_loader_bin + 0xC1E0, 0x10);
	keyRegister("second_loader", "idstorage_smi1_seed",    second_loader_bin + 0xC1C0, 0x20);

	return 0;
}
