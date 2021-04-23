/*
 * SCE Spkg auth code
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/cpu.h>
#include "update_service.h"
#include "sce_self_info.h"

int ksceSblACMgrGetPathId(const char *path, int *pathId);

// TODO:fix this
const SceSelfAuthInfo update_sm = {
	.program_authority_id = 0x2808000000000001,
	.padding1 = 0,
	.capability = {
		.self_type1 = 0x80,
		.self_type2 = 0xC0,
		.unk_0x06 = 0xF0,
		.unk_0x08 = 0x00,
		.unk_0x0C = 0xFFFFFFFF,
		.unk_0x10 = {0, 0, 0, 0}
	},
	.attributes = {
		.unk_0x00 = 0x980,
		.self_type1 = 0x80,
		.self_load_allow_device = 3,
		.unk_0x04 = 0xC30000,
		.unk_0x08 = 0,
		.self_load_allow_path = 0x80,
		.unk_0x0B = 0x9,
		.self_type2 = 0x80,
		.unk_0x10 = {0, 0, 0},
		.unk_0x1C = 0xFFFFFFFF
	},
	.padding2  = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	.klicensee = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	.unk_70 = 0,
	.unk_74 = 0,
	.unk_78 = 0,
	.unk_7C = 0,
	.unk_80 = 0,
	.unk_84 = 0,
	.unk_88 = 0,
	.unk_8C = 0
};

typedef struct SceSblSmCommPair {
	int data_00;
	int data_04;
} SceSblSmCommPair;

int ksceSblSmCommStartSmFromFile(int priority, const char *sm_path, int cmd_id, SceSblSmCommContext130 *ctx130, int *id);

int ksceSblSmCommCallFunc(int id, int service_id, int *f00d_resp, void *data, SceSize size);
int ksceSblSmCommStopSm(int id, SceSblSmCommPair *result);

int update_sm_id;

int start_sm_update(void){

	int res;
	SceSblSmCommContext130 ctx130;

	int perm;

	perm = ksceKernelSetPermission(0x80);

	memset(&ctx130, 0, sizeof(ctx130));
	memcpy(&ctx130.caller_self_auth_info, &update_sm, sizeof(update_sm));

	res = ksceSblACMgrGetPathId("os0:sm/update_service_sm.self", &ctx130.path_id);
	if(res != 0){
		goto error;
	}

	ctx130.self_type = (ctx130.self_type & ~0xF) | 2;	

	res = ksceSblSmCommStartSmFromFile(0, "os0:sm/update_service_sm.self", 0, &ctx130, &update_sm_id);

error:
	ksceKernelSetPermission(perm);
	return res;
}

int stop_sm_update(void){

	SceSblSmCommPair sm_res;

	return ksceSblSmCommStopSm(update_sm_id, &sm_res);
}

typedef struct SceUsAuthArg { // size is 0xFC0
	SceUInt64 data_0x00;
	SceUInt64 data_0x08;
	SceKernelPaddrList PAList[2];
	SceKernelAddrPair PAddrList[0x1F1];
} SceUsAuthArg;

int auth_spkg(void *spkg_address, SceSize size){

	int res = 0, resp = 0;


	void *ptr = ksceKernelAllocHeapMemory(0x1000B, sizeof(SceUsAuthArg) + 0x3F);
	if(ptr == NULL)
		return -1;

	SceUsAuthArg *pUpdateList = (SceUsAuthArg *)((((uintptr_t)ptr) + 0x3F) & ~0x3F);

	memset(pUpdateList, 0, sizeof(*pUpdateList));


	SceKernelAddrPair input;
	input.addr   = (uintptr_t)spkg_address;
	input.length = size;

	pUpdateList->PAList[0].size = sizeof(SceKernelPaddrList);
	pUpdateList->PAList[0].list_size = 0x20;
	pUpdateList->PAList[0].list = pUpdateList->PAddrList;

	ksceKernelGetPaddrList(&input, &pUpdateList->PAList[0]);

	memcpy(&pUpdateList->PAList[1], &pUpdateList->PAList[0], sizeof(SceKernelPaddrList));


	ksceKernelCpuDcacheAndL2WritebackRange(pUpdateList, sizeof(*pUpdateList));

	res = ksceSblSmCommCallFunc(update_sm_id, 0x40002, &resp, pUpdateList, sizeof(*pUpdateList));
	if(res >= 0)
		res = resp;

	ksceKernelCpuDcacheAndL2InvalidateRange(pUpdateList, sizeof(*pUpdateList));

	ksceKernelFreeHeapMemory(0x1000B, ptr);

	return res;
}
