/*
 * PSP2KeyDumper
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2/kernel/clib.h>
#include "psp2keydumper.h"
#include "key.h"
#include "fat16/fat16_api.h"
#include "ref00d/ref00d_kprx_auth.h"

char aimgr_sm[0x15000];

int extract_aimgr_360_key(void){

	int res, fd;

	fd = fatIoOpen("os0:sm/aimgr_sm.self", 1, 0);
	if(fd < 0){
		sceClibPrintf("%s:fatIoOpen failed 0x%X\n", __FUNCTION__, fd);
		return fd;
	}

	res = fatIoRead(fd, aimgr_sm, sizeof(aimgr_sm));
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

	res = ref00d_auth_header(ref00d_ctx, aimgr_sm, 0x1000, &ctx130);
	if(res >= 0)
		res = ref00d_auth_module(ref00d_ctx, aimgr_sm, sm_size);

	ref00d_auth_close(ref00d_ctx);
	ref00d_ctx = 0;

	if(res < 0)
		return res;

	void *aimgr_bin = (void *)(aimgr_sm + 0x1800);

	keyRegister("aimgr", "aimgr_bigmac_seed", aimgr_bin + 0x12CC, 0x10);
	// res <- aes(aimgr_bigmac_seed, bigmac 0x204 key);

	keyRegister("aimgr", "np_passphrase_magic",    aimgr_bin + 0x12C8, 0x4);
	keyRegister("aimgr", "np_passphrase_hmac_key", aimgr_bin + 0x1288, 0x40); // TODO:check
	keyRegister("aimgr", "np_passphrase_enc_key",  aimgr_bin + 0x1278, 0x10); // AES-128-CBC, iv is all zero

	return 0;
}
