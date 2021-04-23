/*
 * PSP2KeyDumper
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2/kernel/clib.h>
#include "psp2keydumper.h"
#include "key.h"
#include "fat16/fat16_api.h"
#include "ref00d/ref00d_kprx_auth.h"

char act_sm[0x15000];

int extract_act_360_key(void){

	int res, fd;

	fd = fatIoOpen("os0:sm/act_sm.self", 1, 0);
	if(fd < 0){
		sceClibPrintf("%s:fatIoOpen failed 0x%X\n", __FUNCTION__, fd);
		return fd;
	}

	res = fatIoRead(fd, act_sm, sizeof(act_sm));
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

	res = ref00d_auth_header(ref00d_ctx, act_sm, 0x1000, &ctx130);
	if(res >= 0)
		res = ref00d_auth_module(ref00d_ctx, act_sm, sm_size);

	ref00d_auth_close(ref00d_ctx);
	ref00d_ctx = 0;

	if(res < 0)
		return res;

	void *act_bin = (void *)(act_sm + 0x1800);

	// maybe has more keys?

	keyRegister("act", "act_aes_cmac_key", act_bin + 0x1F54, 0x20);
	keyRegister("act", "act_aes_iv",       act_bin + 0x1F44, 0x10);
	keyRegister("act", "act_aes_key",      act_bin + 0x1F24, 0x20);
	keyRegister("act", "act_rsa_e",        act_bin + 0x1F1C, 0x4);
	keyRegister("act", "act_rsa_n",        act_bin + 0x1E18, 0x100);

	return 0;
}
