/*
 * PSP2KeyDumper
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/sysmem.h>
#include <psp2/kernel/clib.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/appmgr.h>
#include <psp2/sysmodule.h>
#include <taihen.h>
#include "psp2keydumper.h"
#include "pup.h"
#include "psdif.h"
#include "slb2.h"
#include "key.h"
#include "fat16/fat16_api.h"
#include "ref00d/ref00d_kprx_auth.h"

int write_file(const char *file, const void *data, int size){

	SceUID fd;

	fd = sceIoOpen(file, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);
	if(fd < 0){
		return fd;
	}

	sceIoWrite(fd, data, size);
	sceIoClose(fd);

	return 0;
}

typedef struct SceSysmoduleOpt {
	int flags;
	int *result;
	int unused[2];
} SceSysmoduleOpt;

typedef struct ScePafInit { // size is 0x18
	SceSize global_heap_size;
	int a2;
	int a3;
	int use_gxm;
	int heap_opt_param1;
	int heap_opt_param2;
} ScePafInit;

int load_paf(void){

	int res, load_res;
	ScePafInit init_param;
	SceSysmoduleOpt sysmodule_opt;

	init_param.global_heap_size = 0x2000000; // 32MiB
	init_param.a2               = 0xFFFFFFFF;
	init_param.a3               = 0xFFFFFFFF;
	init_param.use_gxm          = 0;
	init_param.heap_opt_param1  = 1;
	init_param.heap_opt_param2  = 1;

	load_res = -1;
	sysmodule_opt.flags  = 0x10; // module load flags
	sysmodule_opt.result = &load_res;

	res = sceSysmoduleLoadModuleInternalWithArg(SCE_SYSMODULE_INTERNAL_PAF, sizeof(init_param), &init_param, &sysmodule_opt);
	if(res >= 0)
		res = load_res;

	return res;
}

typedef struct SceDmac5EncdecCtx {
	const void *src;
	void       *dst;
	SceSize     size;
	const void *key;
	SceSize     key_size; // (int bits)
	void       *iv;
} SceDmac5EncdecCtx;

int sceSblDmac5EncDec(SceDmac5EncdecCtx *ctx, int command);

typedef struct SceKernelAddrPair {
	uint32_t addr;                  //!< Address
	uint32_t length;                //!< Length
} SceKernelAddrPair;

typedef struct AuthArg {
	SceUID pid;
	int cmd;
	SceKernelAddrPair buffer;
	SceInt32 *res;
} AuthArg;

const char enc_magic[4] = {0xE5, 0xC8, 0xB2, 0x64};

char root_key[0x10], slb2_buffer[0x400000] __attribute__((aligned(0x40)));

int deviceId;

int slb2ReadSector(SceUInt32 sector_pos, void *data, SceUInt32 sector_num){
	return psdifReadSector(deviceId, sector_pos, data, sector_num);
}

int decrypt_enc(SceSlb2Context *pSlb2Ctx, const char *name, void *data, SceSize *length){

	int fd, res;

	fd = sceSlb2Open(pSlb2Ctx, name);
	if(fd < 0){
		sceClibPrintf("%s:sceSlb2Open 0x%X\n", __FUNCTION__, fd);
	}

	res = sceSlb2Read(pSlb2Ctx, fd, data, *length);
	sceSlb2Close(pSlb2Ctx, fd);

	if(res <= 0){
		sceClibPrintf("%s:Cannot read second_loader.\n", __FUNCTION__);
		return -1;
	}

	if(res < 0x1000){
		sceClibPrintf("%s:Invalid second_loader.\n", __FUNCTION__);
		return -1;
	}

	if(sceClibMemcmp(data, enc_magic, sizeof(enc_magic)) != 0){
		sceClibPrintf("%s:Enc magic not match.\n", __FUNCTION__);
		return -1;
	}

	if(sceClibStrncmp(data + 0x40, "0000360000000000", 0x10) != 0){
		sceClibPrintf("%s:Enc version not match.\n", __FUNCTION__);
		return -1;
	}

	*length = res;

	char iv[0x10];
	SceDmac5EncdecCtx ctx;

	sceClibMemset(iv, 0, 16);

	ctx.src      = data + 0x2C0;
	ctx.dst      = data + 0x2C0;
	ctx.size     = res - 0x2C0;
	ctx.key      = root_key;
	ctx.iv       = iv;
	ctx.key_size = 128;

	return sceSblDmac5EncDec(&ctx, 0x10A);
}

int psp2keydumper_send_cmd(int cmd, void *data, SceSize length){

	int res, cmd_res = -1;

	AuthArg auth_args;
	auth_args.pid           = sceKernelGetProcessId();
	auth_args.cmd           = cmd;
	auth_args.buffer.addr   = (uintptr_t)data;
	auth_args.buffer.length = length;
	auth_args.res           = &cmd_res;

	res = taiLoadStartKernelModule("ux0:app/VKEY00001/psp2keydumper.skprx", sizeof(auth_args), &auth_args, 0);
	if(res == 0x80024501)
		res = 0;

	if(res >= 0)
		res = cmd_res;

	return res;
}

int load_slb2(ScePupContext *pContext){

	int res;

	res = scePupRead(pContext, 0x302, slb2_buffer, sizeof(slb2_buffer));
	if(res <= 0){
		return res;
	}

	res = psp2keydumper_send_cmd(0, slb2_buffer, sizeof(slb2_buffer));
	if(res < 0){
		sceClibPrintf("%s:psp2keydumper(kernel) failed : 0x%X\n", __FUNCTION__, res);
		return res;
	}

	res = psdifRegisterDevice(slb2_buffer + 0x480, res - 0x480);
	if(res < 0){
		sceClibPrintf("%s:psdifRegisterDevice:0x%X\n", __FUNCTION__, res);
		return res;
	}

	deviceId = res;

	return 0;
}

SceUID device_os0_memid;
void *pDeviceOs0;

int fatReadSectorOs0(void *args, uint32_t start_sector, void *buf, uint32_t read_sector_num){
	sceClibMemcpy(buf, pDeviceOs0 + (start_sector << 9), read_sector_num << 9);
	return 0;
}

char segment_tmp[0x801000];

int load_os0(ScePupContext *pContext){

	int res;

	device_os0_memid = sceKernelAllocMemBlock("SceDeviceOs0", 0x0C20D060, 0x1000000, NULL);
	if(device_os0_memid < 0){
		sceClibPrintf("%s:sceKernelAloocMemBlock failed : 0x%X\n", __FUNCTION__, device_os0_memid);
		return device_os0_memid;
	}

	sceKernelGetMemBlockBase(device_os0_memid, &pDeviceOs0);

	sceClibMemset(pDeviceOs0, 0, 0x1000000);

#define SCE_SBL_SPKG_TYPE_OS0 (1)

	res = scePupReadBySpkgType(pContext, SCE_SBL_SPKG_TYPE_OS0, 1, segment_tmp, sizeof(segment_tmp));
	if(res < 0)
		return res;

	if(res == 0)
		return -1;

	int size = res;

	res = psp2keydumper_send_cmd(0, segment_tmp, res);
	if(res < 0){
		sceClibPrintf("%s:spkg auth failed : 0x%X\n", __FUNCTION__, res);
		return res;
	}

	sceClibMemcpy(pDeviceOs0, &segment_tmp[0x480], size - 0x480);

	res = fatAddPartCtx("os0:", FAT16_PART_RERMISSION_RD, NULL, 0, fatReadSectorOs0, NULL);
	if(res < 0){
		sceClibPrintf("%s:fatAddPartCtx failed : 0x%X\n", __FUNCTION__, res);
		return res;
	}

	return 0;
}

int dump_vita_keys(SceSlb2Context *pSlb2Ctx){

	int res;

	res = extract_second_loader_360_key(pSlb2Ctx);
	if(res < 0){
		sceClibPrintf("%s:extract_second_loader_360_key 0x%X\n", __FUNCTION__, res);
		return res;
	}

	res = extract_secure_kernel_360_key(pSlb2Ctx);
	if(res < 0){
		sceClibPrintf("%s:extract_secure_kernel_360_key 0x%X\n", __FUNCTION__, res);
		return res;
	}

	char security_module_key[0x20];
	char security_module_iv[0x10];

	res = keyGetRegisteredKey("security_module_key", security_module_key, sizeof(security_module_key));
	if(res >= 0)
		res = keyGetRegisteredKey("security_module_iv",  security_module_iv,  sizeof(security_module_iv));

	if(res < 0){
		sceClibPrintf("%s:Failed to get sm keyset 0x%X\n", __FUNCTION__, res);
		return res;
	}

	ref00d_auth_set_key(security_module_key, security_module_iv, sizeof(security_module_key));

	if(1){
		extract_kprx_auth_360_key(pSlb2Ctx);
		extract_update_service_360_key();
		extract_act_360_key();
		extract_qaf_360_key();
		extract_pm_360_key();
		extract_aimgr_360_key();
		extract_encdec_w_portability_360_key();

		// Many unknown keys
		// gcauthmgr_sm
		// rmauth_sm
		// mgkm_sm
		// utoken_sm
		// compat_sm
		// spkg_verifier_sm_w_key
	}

	return 0;
}

int load_pup_360(void){

	int res;
	ScePupContext pup_ctx;

	res = scePupOpen(&pup_ctx, "host0:data/PSP2UPDAT.PUP");
	if(res < 0)
		res = scePupOpen(&pup_ctx, "ux0:app/VKEY00001/PSP2UPDAT.PUP");
	if(res < 0)
		res = scePupOpen(&pup_ctx, "app0:PSP2UPDAT.PUP");
	if(res < 0){
		sceClibPrintf("%s:scePupOpen failed:0x%X\n", __FUNCTION__, res);
		return res;
	}

	if(0)
		scePupPrintEntrys(&pup_ctx);

	res = load_slb2(&pup_ctx);
	if(res >= 0)
		res = load_os0(&pup_ctx);

	scePupClose(&pup_ctx);

	if(res < 0){
		sceClibPrintf("%s:load slb2 or os0 failed : 0x%X\n", __FUNCTION__, res);
	}

	return 0;
}

int save_keys(void){

	SceIoStat stat;
	const char *drv = "host0:data/vita_key/";

	if(sceIoGetstat(drv, &stat) < 0)
		drv = "sd0:data/vita_key/";

	if(sceIoGetstat(drv, &stat) < 0)
		drv = "ux0:data/vita_key/";

	if(sceIoGetstat(drv, &stat) >= 0){
		keySaveRegisteredKeys(drv);
		sceClibPrintf("Key saved to %s.\n", drv);
	}else{
		sceClibPrintf("Save path not found.\n");
		sceClibPrintf("  -> Exit app without save keys\n");
	}

	return 0;
}

void _start() __attribute__ ((weak, alias("module_start")));
int module_start(SceSize args, void *argp){

	int res;

	res = load_paf();
	if(res < 0){
		sceClibPrintf("%s:load_paf failed : 0x%X\n", __FUNCTION__, res);
		return 0;
	}

	res = ref00d_kprx_auth_initialization();
	if(res < 0){
		sceClibPrintf("%s:ref00d_kprx_auth_initialization failed : 0x%X\n", __FUNCTION__, res);
		return 0;
	}

	res = load_pup_360();
	if(res < 0){
		sceClibPrintf("%s:load_pup_360 failed : 0x%X\n", __FUNCTION__, res);
		return 0;
	}

	res = psp2keydumper_send_cmd(1, root_key, sizeof(root_key));
	if(res < 0){
		sceClibPrintf("%s:psp2keydumper(kernel) failed : 0x%X\n", __FUNCTION__, res);
		return 0;
	}

	SceSlb2Context slb2_ctx;

	res = sceSlb2InitializeContext(&slb2_ctx, slb2ReadSector);
	if(res < 0){
		sceClibPrintf("%s:sceSlb2InitializeContext:0x%X\n", __FUNCTION__, res);
		return 0;
	}

	dump_vita_keys(&slb2_ctx);

	save_keys();

	res = psdifUnregisterDevice(deviceId);
	if(res < 0){
		sceClibPrintf("%s:psdifUnregisterDevice:0x%X\n", __FUNCTION__, res);
		return 0;
	}

	deviceId = -1;

	sceClibPrintf("All OK\n");

	sceAppMgrDestroyAppByAppId(~2);

	return 0;
}
