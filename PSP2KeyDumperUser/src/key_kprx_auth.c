/*
 * PSP2KeyDumper
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2/kernel/clib.h>
#include "psp2keydumper.h"
#include "key.h"
#include "slb2.h"
#include "ref00d/ref00d_kprx_auth.h"

char kprx_buffer[0x15000] __attribute__((aligned(0x40)));

int extract_kprx_auth_360_key(SceSlb2Context *pSlb2Ctx){

	int fd, res;

	fd = sceSlb2Open(pSlb2Ctx, "kprx_auth_sm.self");
	if(fd < 0){
		sceClibPrintf("%s:sceSlb2Open 0x%X\n", __FUNCTION__, fd);
	}

	res = sceSlb2Read(pSlb2Ctx, fd, kprx_buffer, sizeof(kprx_buffer));
	sceSlb2Close(pSlb2Ctx, fd);
	if(res < 0){
		sceClibPrintf("%s:sceSlb2Read failed : 0x%X\n", __FUNCTION__, res);
		return res;
	}

	int sm_size = res;
	int ref00d_ctx = 0;
	SceSblSmCommContext130 ctx130;
	sceClibMemset(&ctx130, 0, sizeof(ctx130));

	ref00d_auth_open(&ref00d_ctx);

	res = ref00d_auth_header(ref00d_ctx, kprx_buffer, 0x1000, &ctx130);
	if(res >= 0)
		res = ref00d_auth_module(ref00d_ctx, kprx_buffer, sm_size);

	ref00d_auth_close(ref00d_ctx);
	ref00d_ctx = 0;

	if(res < 0)
		return res;

	void *kprx_auth_bin = kprx_buffer + 0x1800;

	if(sceClibMemcmp(kprx_auth_bin + 0x5530, kprx_auth_bin + 0x5550, 0x10) != 0){
		sceClibPrintf("%s:Kprx_auth could not be decrypted correctly.\n", __FUNCTION__);
		return -1;
	}

	// has more unknown keysets

	// 0x72DC - 0x733B : unknown keys

	keyRegister("kprx_auth_ver2", "kprx_unk_0x72BC", kprx_auth_bin + 0x72BC, 0x20);
	keyRegister("kprx_auth_ver2", "kprx_npdrm_iv1",  kprx_auth_bin + 0x72AC, 0x10);
	keyRegister("kprx_auth_ver2", "kprx_npdrm_key1", kprx_auth_bin + 0x729C, 0x10);
	keyRegister("kprx_auth_ver2", "kprx_npdrm_iv0",  kprx_auth_bin + 0x728C, 0x10);
	keyRegister("kprx_auth_ver2", "kprx_npdrm_key0", kprx_auth_bin + 0x727C, 0x10);

	keyRegister("kprx_auth_ver2", "EKc_type2", kprx_auth_bin + 0x725C, 0x20);
	keyRegister("kprx_auth_ver2", "EKc_type1", kprx_auth_bin + 0x723C, 0x20);
	keyRegister("kprx_auth_ver2", "EKc_type0", kprx_auth_bin + 0x721C, 0x20);

	keyRegister("kprx_auth_ver2", "kprx_auth_app_rev5_rsa_e", kprx_auth_bin + 0x7214, 0x4);
	keyRegister("kprx_auth_ver2", "kprx_auth_app_rev5_rsa_n", kprx_auth_bin + 0x7110, 0x100);
	keyRegister("kprx_auth_ver2", "kprx_auth_app_rev5_iv",    kprx_auth_bin + 0x7100, 0x10);
	keyRegister("kprx_auth_ver2", "kprx_auth_app_rev5_key",   kprx_auth_bin + 0x70E0, 0x20);

	keyRegister("kprx_auth_ver2", "kprx_auth_unk_0x70C0_key", kprx_auth_bin + 0x70C0, 0x20);

	keyRegister("kprx_auth_ver2", "kprx_auth_app_rev4_rsa_e", kprx_auth_bin + 0x70B8, 0x4);
	keyRegister("kprx_auth_ver2", "kprx_auth_app_rev4_rsa_n", kprx_auth_bin + 0x6FB4, 0x100);
	keyRegister("kprx_auth_ver2", "kprx_auth_app_rev4_iv",    kprx_auth_bin + 0x6FA4, 0x10);
	keyRegister("kprx_auth_ver2", "kprx_auth_app_rev4_key",   kprx_auth_bin + 0x6F84, 0x20);

	keyRegister("kprx_auth_ver2", "kprx_auth_unk_0x6F64_key", kprx_auth_bin + 0x6F64, 0x20);

	keyRegister("kprx_auth_ver2", "kprx_auth_app_rev3_rsa_e", kprx_auth_bin + 0x6F5C, 0x4);
	keyRegister("kprx_auth_ver2", "kprx_auth_app_rev3_rsa_n", kprx_auth_bin + 0x6E58, 0x100);
	keyRegister("kprx_auth_ver2", "kprx_auth_app_rev3_iv",    kprx_auth_bin + 0x6E48, 0x10);
	keyRegister("kprx_auth_ver2", "kprx_auth_app_rev3_key",   kprx_auth_bin + 0x6E28, 0x20);

	keyRegister("kprx_auth_ver2", "kprx_auth_unk_0x6E08_key", kprx_auth_bin + 0x6E08, 0x20);

	keyRegister("kprx_auth_ver2", "kprx_auth_app_rev2_rsa_e", kprx_auth_bin + 0x6E00, 0x4);
	keyRegister("kprx_auth_ver2", "kprx_auth_app_rev2_rsa_n", kprx_auth_bin + 0x6CFC, 0x100);
	keyRegister("kprx_auth_ver2", "kprx_auth_app_rev2_iv",    kprx_auth_bin + 0x6CEC, 0x10);
	keyRegister("kprx_auth_ver2", "kprx_auth_app_rev2_key",   kprx_auth_bin + 0x6CCC, 0x20);

	keyRegister("kprx_auth_ver2", "kprx_auth_unk_0x6CAC_key", kprx_auth_bin + 0x6CAC, 0x20);

	keyRegister("kprx_auth_ver2", "kprx_auth_app_rev1_rsa_e", kprx_auth_bin + 0x6CA4, 0x4);
	keyRegister("kprx_auth_ver2", "kprx_auth_app_rev1_rsa_n", kprx_auth_bin + 0x6BA0, 0x100);
	keyRegister("kprx_auth_ver2", "kprx_auth_app_rev1_iv",    kprx_auth_bin + 0x6B90, 0x10);
	keyRegister("kprx_auth_ver2", "kprx_auth_app_rev1_key",   kprx_auth_bin + 0x6B70, 0x20);

	keyRegister("kprx_auth_ver2", "kprx_auth_unk_0x6B50_key", kprx_auth_bin + 0x6B50, 0x20);

	keyRegister("kprx_auth_ver2", "kprx_auth_app_rev0_rsa_e", kprx_auth_bin + 0x6B48, 0x4);
	keyRegister("kprx_auth_ver2", "kprx_auth_app_rev0_rsa_n", kprx_auth_bin + 0x6A44, 0x100);
	keyRegister("kprx_auth_ver2", "kprx_auth_app_rev0_iv",    kprx_auth_bin + 0x6A34, 0x10);
	keyRegister("kprx_auth_ver2", "kprx_auth_app_rev0_key",   kprx_auth_bin + 0x6A14, 0x20);

	keyRegister("kprx_auth_ver2", "kprx_auth_unk_0x69F4_key", kprx_auth_bin + 0x69F4, 0x20);

	keyRegister("kprx_auth_ver2", "kprx_auth_system_rev3_rsa_e", kprx_auth_bin + 0x69EC, 0x4);
	keyRegister("kprx_auth_ver2", "kprx_auth_system_rev3_rsa_n", kprx_auth_bin + 0x68E8, 0x100);
	keyRegister("kprx_auth_ver2", "kprx_auth_system_rev3_iv",    kprx_auth_bin + 0x68D8, 0x10);
	keyRegister("kprx_auth_ver2", "kprx_auth_system_rev3_key",   kprx_auth_bin + 0x68B8, 0x20);

	keyRegister("kprx_auth_ver2", "kprx_auth_system_rev2_rsa_e", kprx_auth_bin + 0x68B0, 0x4);
	keyRegister("kprx_auth_ver2", "kprx_auth_system_rev2_rsa_n", kprx_auth_bin + 0x67AC, 0x100);
	keyRegister("kprx_auth_ver2", "kprx_auth_system_rev2_iv",    kprx_auth_bin + 0x679C, 0x10);
	keyRegister("kprx_auth_ver2", "kprx_auth_system_rev2_key",   kprx_auth_bin + 0x677C, 0x20);

	keyRegister("kprx_auth_ver2", "kprx_auth_system_rev1_rsa_e", kprx_auth_bin + 0x6774, 0x4);
	keyRegister("kprx_auth_ver2", "kprx_auth_system_rev1_rsa_n", kprx_auth_bin + 0x6670, 0x100);
	keyRegister("kprx_auth_ver2", "kprx_auth_system_rev1_iv",    kprx_auth_bin + 0x6660, 0x10);
	keyRegister("kprx_auth_ver2", "kprx_auth_system_rev1_key",   kprx_auth_bin + 0x6640, 0x20);

	keyRegister("kprx_auth_ver2", "kprx_auth_system_rev0_rsa_e", kprx_auth_bin + 0x6638, 0x4);
	keyRegister("kprx_auth_ver2", "kprx_auth_system_rev0_rsa_n", kprx_auth_bin + 0x6534, 0x100);
	keyRegister("kprx_auth_ver2", "kprx_auth_system_rev0_iv",    kprx_auth_bin + 0x6524, 0x10);
	keyRegister("kprx_auth_ver2", "kprx_auth_system_rev0_key",   kprx_auth_bin + 0x6504, 0x20);

	keyRegister("kprx_auth_ver2", "kprx_auth_unk_0x64FC_rsa_e", kprx_auth_bin + 0x64FC, 0x4);
	keyRegister("kprx_auth_ver2", "kprx_auth_unk_0x63F8_rsa_n", kprx_auth_bin + 0x63F8, 0x100);
	keyRegister("kprx_auth_ver2", "kprx_auth_unk_0x63E8_iv",    kprx_auth_bin + 0x63E8, 0x10);
	keyRegister("kprx_auth_ver2", "kprx_auth_unk_0x63C8_key",   kprx_auth_bin + 0x63C8, 0x20);

	keyRegister("kprx_auth_ver2", "kprx_auth_kernel_rsa_e", kprx_auth_bin + 0x63C0, 0x4);
	keyRegister("kprx_auth_ver2", "kprx_auth_kernel_rsa_n", kprx_auth_bin + 0x62BC, 0x100);
	keyRegister("kprx_auth_ver2", "kprx_auth_kernel_iv",    kprx_auth_bin + 0x62AC, 0x10);
	keyRegister("kprx_auth_ver2", "kprx_auth_kernel_key",   kprx_auth_bin + 0x628C, 0x20);

	keyRegister("kprx_auth_ver2", "spsfo_qa_5_rsa_e", kprx_auth_bin + 0x6280, 0x4);
	keyRegister("kprx_auth_ver2", "spsfo_qa_5_rsa_n", kprx_auth_bin + 0x617C, 0x100);
	keyRegister("kprx_auth_ver2", "spsfo_qa_5_iv",    kprx_auth_bin + 0x616C, 0x10);
	keyRegister("kprx_auth_ver2", "spsfo_qa_5_key",   kprx_auth_bin + 0x614C, 0x20);

	keyRegister("kprx_auth_ver2", "spsfo_qa_3_rsa_e", kprx_auth_bin + 0x6144, 0x4);
	keyRegister("kprx_auth_ver2", "spsfo_qa_3_rsa_n", kprx_auth_bin + 0x6040, 0x100);
	keyRegister("kprx_auth_ver2", "spsfo_qa_3_iv",    kprx_auth_bin + 0x6030, 0x10);
	keyRegister("kprx_auth_ver2", "spsfo_qa_3_key",   kprx_auth_bin + 0x6010, 0x20);

	keyRegister("kprx_auth_ver2", "spsfo_qa_01_rsa_e", kprx_auth_bin + 0x6008, 0x4);
	keyRegister("kprx_auth_ver2", "spsfo_qa_01_rsa_n", kprx_auth_bin + 0x5F04, 0x100);
	keyRegister("kprx_auth_ver2", "spsfo_qa_01_iv",    kprx_auth_bin + 0x5EF4, 0x10);
	keyRegister("kprx_auth_ver2", "spsfo_qa_01_key",   kprx_auth_bin + 0x5ED4, 0x20);

	keyRegister("kprx_auth_ver2", "spsfo_rsa_e", kprx_auth_bin + 0x58A0, 0x4);
	keyRegister("kprx_auth_ver2", "spsfo_rsa_n", kprx_auth_bin + 0x579C, 0x100);
	keyRegister("kprx_auth_ver2", "spsfo_iv",    kprx_auth_bin + 0x578C, 0x10);
	keyRegister("kprx_auth_ver2", "spsfo_key",   kprx_auth_bin + 0x576C, 0x20);

	return 0;
}
