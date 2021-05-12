/*
 * PSP2KeyDumper
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2/kernel/clib.h>
#include "psp2keydumper.h"
#include "key.h"
#include "fat16/fat16_api.h"
#include "ref00d/ref00d_kprx_auth.h"

char gcauthmgr_sm[0x15000];

int extract_gcauthmgr_360_key(void){

	int res, fd;

	fd = fatIoOpen("os0:sm/gcauthmgr_sm.self", 1, 0);
	if(fd < 0){
		sceClibPrintf("%s:fatIoOpen failed 0x%X\n", __FUNCTION__, fd);
		return fd;
	}

	res = fatIoRead(fd, gcauthmgr_sm, sizeof(gcauthmgr_sm));
	fatIoClose(fd);
	if(res < 0){
		sceClibPrintf("%s:fatIoRead failed 0x%X\n", __FUNCTION__, fd);
		return fd;
	}

	int sm_size = res;
	int ref00d_ctx = 0;
	SceSblSmCommContext130 ctx130;
	sceClibMemset(&ctx130, 0, sizeof(ctx130));

	ref00d_auth_open(&ref00d_ctx);

	res = ref00d_auth_header(ref00d_ctx, gcauthmgr_sm, 0x1000, &ctx130);
	if(res >= 0)
		res = ref00d_auth_module(ref00d_ctx, gcauthmgr_sm, sm_size);

	ref00d_auth_close(ref00d_ctx);
	ref00d_ctx = 0;

	if(res < 0)
		return res;

	void *gcauthmgr_bin = (void *)(gcauthmgr_sm + 0x1800);

	keyRegister("gcauthmgr", "ecdsa160_Gy", gcauthmgr_bin + 0x7DDC, 0x14);
	keyRegister("gcauthmgr", "ecdsa160_Gx", gcauthmgr_bin + 0x7DC8, 0x14);
	keyRegister("gcauthmgr", "ecdsa160_N",  gcauthmgr_bin + 0x7DB4, 0x14);
	keyRegister("gcauthmgr", "ecdsa160_B",  gcauthmgr_bin + 0x7DA0, 0x14);
	keyRegister("gcauthmgr", "ecdsa160_A",  gcauthmgr_bin + 0x7D8C, 0x14);
	keyRegister("gcauthmgr", "ecdsa160_P",  gcauthmgr_bin + 0x7D78, 0x14);

	keyRegister("gcauthmgr", "ecdsa224_Gy", gcauthmgr_bin + 0x7D5C, 0x1C);
	keyRegister("gcauthmgr", "ecdsa224_Gx", gcauthmgr_bin + 0x7D40, 0x1C);
	keyRegister("gcauthmgr", "ecdsa224_N",  gcauthmgr_bin + 0x7D24, 0x1C);
	keyRegister("gcauthmgr", "ecdsa224_B",  gcauthmgr_bin + 0x7D08, 0x1C);
	keyRegister("gcauthmgr", "ecdsa224_A",  gcauthmgr_bin + 0x7CEC, 0x1C);
	keyRegister("gcauthmgr", "ecdsa224_P",  gcauthmgr_bin + 0x7CD0, 0x1C);

	// This seed is to aes src. Aes128Ecb(seed, bigmacKeyslot0x204) -> Cert crypto key (with zero iv)
	keyRegister("gcauthmgr", "gcauthmgr_kirk_cert_priv_key_enc_seed", gcauthmgr_bin + 0x7580, 0x10);

	return 0;
}
