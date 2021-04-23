/*
 * PSP2KeyDumper
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2/kernel/clib.h>
#include <psp2/paf.h>
#include "psp2keydumper.h"
#include "key.h"
#include "fat16/fat16_api.h"
#include "ref00d/ref00d_kprx_auth.h"

char encdec_w_portability_sm[0x15000];

int extract_encdec_w_portability_360_key(void){

	int res, fd;

	fd = fatIoOpen("os0:sm/encdec_w_portability_sm.self", 1, 0);
	if(fd < 0){
		sceClibPrintf("%s:fatIoOpen failed 0x%X\n", __FUNCTION__, fd);
		return fd;
	}

	res = fatIoRead(fd, encdec_w_portability_sm, sizeof(encdec_w_portability_sm));
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

	res = ref00d_auth_header(ref00d_ctx, encdec_w_portability_sm, 0x1000, &ctx130);
	if(res >= 0)
		res = ref00d_auth_module(ref00d_ctx, encdec_w_portability_sm, sm_size);

	ref00d_auth_close(ref00d_ctx);
	ref00d_ctx = 0;

	if(res < 0)
		return res;

	void *encdec_w_portability_bin = (void *)(encdec_w_portability_sm + 0x1800);

	char name[0x20];

	for(int i=0;i<0x14;i++){

		sce_paf_private_snprintf(name, sizeof(name), "encdec_w_portability_key%d", i + 1);

		keyRegister("encdec_w_portability", name, encdec_w_portability_bin + 0x9C0 + (0x20 * i), 0x20);
	}

	return 0;
}
