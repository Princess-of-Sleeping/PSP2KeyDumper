/*
 * PSP2KeyDumper
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2/kernel/clib.h>
#include "psp2keydumper.h"
#include "key.h"
#include "fat16/fat16_api.h"
#include "ref00d/ref00d_kprx_auth.h"

char update_service_sm[0x15000];

int extract_update_service_360_key(void){

	int res, fd;

	fd = fatIoOpen("os0:sm/update_service_sm.self", 1, 0);
	if(fd < 0){
		sceClibPrintf("%s:fatIoOpen failed 0x%X\n", __FUNCTION__, fd);
		return fd;
	}

	res = fatIoRead(fd, update_service_sm, sizeof(update_service_sm));
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

	res = ref00d_auth_header(ref00d_ctx, update_service_sm, 0x1000, &ctx130);
	if(res >= 0)
		res = ref00d_auth_module(ref00d_ctx, update_service_sm, sm_size);

	ref00d_auth_close(ref00d_ctx);
	ref00d_ctx = 0;

	if(res < 0)
		return res;

	void *update_service_bin = (void *)(update_service_sm + 0x1800);

	keyRegister("update_service", "spkg_auth_rsa_e", update_service_bin + 0x8C40, 0x4);
	keyRegister("update_service", "spkg_auth_rsa_n", update_service_bin + 0x8B3C, 0x100);
	keyRegister("update_service", "spkg_auth_iv",    update_service_bin + 0x8B2C, 0x10);
	keyRegister("update_service", "spkg_auth_key",   update_service_bin + 0x8B0C, 0x20);

	// 0x8A80 : unknown keys

	char key_name[0x40];

	for(int i=0;i<0xA;i++){
		sceClibSnprintf(key_name, sizeof(key_name), "us_hmac_key%d", 10 - i);
		keyRegister("update_service", key_name, update_service_bin + 0x7D98 + (0x40 * (10 - i - 1)), 0x40);
	}

	// 0x7D54 : syscon keys x1
	// 0x7CDC : syscon keys x4

	// 0x79F8 - 0x7C87 : unknown keys

	keyRegister("update_service", "pup_wm_iv",  update_service_bin + 0x79E8, 0x10);
	keyRegister("update_service", "pup_wm_key", update_service_bin + 0x79D8, 0x10);
	keyRegister("update_service", "pup_as_iv",  update_service_bin + 0x7748, 0x10);
	keyRegister("update_service", "pup_as_key", update_service_bin + 0x7738, 0x10);

	keyRegister("update_service", "pup_wm_rsa_e", update_service_bin + 0x7730, 0x4);
	keyRegister("update_service", "pup_wm_rsa_n", update_service_bin + 0x762C, 0x100);
	keyRegister("update_service", "pup_as_rsa_e", update_service_bin + 0x7604, 0x4);
	keyRegister("update_service", "pup_as_rsa_n", update_service_bin + 0x7500, 0x100);

	return 0;
}
