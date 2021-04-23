/*
 * PSP2KeyDumper
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2/kernel/clib.h>
#include "psp2keydumper.h"
#include "key.h"
#include "fat16/fat16_api.h"
#include "ref00d/ref00d_kprx_auth.h"

char qaf_sm[0x15000];

int extract_qaf_360_key(void){

	int res, fd;

	fd = fatIoOpen("os0:sm/qaf_sm.self", 1, 0);
	if(fd < 0){
		sceClibPrintf("%s:fatIoOpen failed 0x%X\n", __FUNCTION__, fd);
		return fd;
	}

	res = fatIoRead(fd, qaf_sm, sizeof(qaf_sm));
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

	res = ref00d_auth_header(ref00d_ctx, qaf_sm, 0x1000, &ctx130);
	if(res >= 0)
		res = ref00d_auth_module(ref00d_ctx, qaf_sm, sm_size);

	ref00d_auth_close(ref00d_ctx);
	ref00d_ctx = 0;

	if(res < 0)
		return res;

	void *qaf_bin = (void *)(qaf_sm + 0x1800);

	// maybe has more keys?

	keyRegister("qaf", "qaf_rsa_e", qaf_bin + 0x3D84, 0x4);
	keyRegister("qaf", "qaf_rsa_n", qaf_bin + 0x3C80, 0x100);

	return 0;
}
