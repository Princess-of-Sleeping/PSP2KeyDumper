/*
 * PSP2KeyDumper
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2/kernel/clib.h>
#include "psp2keydumper.h"
#include "key.h"
#include "fat16/fat16_api.h"
#include "ref00d/ref00d_kprx_auth.h"

char pm_sm[0x15000];

int extract_pm_360_key(void){

	int res, fd;

	fd = fatIoOpen("os0:sm/pm_sm.self", 1, 0);
	if(fd < 0){
		sceClibPrintf("%s:fatIoOpen failed 0x%X\n", __FUNCTION__, fd);
		return fd;
	}

	res = fatIoRead(fd, pm_sm, sizeof(pm_sm));
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

	res = ref00d_auth_header(ref00d_ctx, pm_sm, 0x1000, &ctx130);
	if(res >= 0)
		res = ref00d_auth_module(ref00d_ctx, pm_sm, sm_size);

	ref00d_auth_close(ref00d_ctx);
	ref00d_ctx = 0;

	if(res < 0)
		return res;

	void *pm_bin = (void *)(pm_sm + 0x1800);

	keyRegister("pm", "pm_unk_0x4148_rsa_e", pm_bin + 0x4148, 0x4);
	keyRegister("pm", "pm_unk_0x4048_rsa_n", pm_bin + 0x4048, 0x100);

	keyRegister("pm", "pm_unk_0x4044_rsa_e", pm_bin + 0x4044, 0x4);
	keyRegister("pm", "pm_unk_0x3F44_rsa_n", pm_bin + 0x3F44, 0x100);

	// 0x3DE8 - 0x3E67 : unknown keys
	// 0x3EDC(0x20 byte):unknown key or iv

	return 0;
}
