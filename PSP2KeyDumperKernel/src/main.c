/*
 * PSP2KeyDumperKernel
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/io/fcntl.h>
#include "spkg_auth.h"

typedef struct AuthArg {
	SceUID pid;
	int cmd;
	SceKernelAddrPair buffer;
	SceInt32 *res;
} AuthArg;

int run_on_thread(const void *func, SceSize args, void *argp){

	int ret = 0, res = 0;
	SceUID uid;

	ret = uid = ksceKernelCreateThread("run_on_thread", func, 64, 0x2000, 0, 0, 0);

	if (ret < 0) {
		ksceDebugPrintf("failed to create a thread: 0x%08x\n", ret);
		ret = -1;
		goto cleanup;
	}
	if ((ret = ksceKernelStartThread(uid, args, argp)) < 0) {
		ksceDebugPrintf("failed to start a thread: 0x%08x\n", ret);
		ret = -1;
		goto cleanup;
	}
	if ((ret = ksceKernelWaitThreadEnd(uid, &res, NULL)) < 0) {
		ksceDebugPrintf("failed to wait a thread: 0x%08x\n", ret);
		ret = -1;
		goto cleanup;
	}

	ret = res;

cleanup:
	if (uid > 0)
		ksceKernelDeleteThread(uid);

	return ret;
}

int sceUsSpkgAuthThread(SceSize args, AuthArg *argp){

	int res = -1;

	void *spkg_base;

	SceUID memid = ksceKernelAllocMemBlock("spkg_temp_buffer", 0x30808006, 0x801000, NULL);
	ksceKernelGetMemBlockBase(memid, &spkg_base);

	ksceKernelMemcpyUserToKernelForPid(argp->pid, spkg_base, argp->buffer.addr, argp->buffer.length);

	if(1){
		start_sm_update();

		res = auth_spkg(spkg_base, argp->buffer.length);

		stop_sm_update();

		if(res >= 0){
			ksceKernelMemcpyKernelToUserForPid(argp->pid, argp->buffer.addr, spkg_base, argp->buffer.length);
		}
	}

	ksceKernelFreeMemBlock(memid);

	return res;
}

int read_last_block(const char *device, void *dst){

	int res;
	SceUID fd;

	fd = ksceIoOpen(device, SCE_O_RDONLY, 0777);
	if(fd < 0){
		ksceDebugPrintf("%s:sceIoOpen:0x%X\n", __FUNCTION__, fd);
		return fd;
	}

	SceOff device_size = ksceIoLseek(fd, 0LL, SCE_SEEK_END);
	if(device_size < 0){
		res = (int)device_size;
		goto error;
	}

	if(device_size > 0xFFFFFFFF){
		res = -1;
		goto error;
	}

	device_size = ksceIoLseek(fd, 0xC0000, SCE_SEEK_SET);
	ksceIoRead(fd, dst, 0x10);

	res = 0;

error:
	if(fd >= 0)
		ksceIoClose(fd);

	return res;
}

int rootKeyGetThread(SceSize args, AuthArg *argp){

	int res;
	char key[0x10];

	memset(key, 0, sizeof(key));

	res = read_last_block("sdstor0:int-lp-ina-sloader", key);
	if(res >= 0){
		ksceKernelMemcpyKernelToUserForPid(argp->pid, argp->buffer.addr, key, 0x10);
	}else{
		ksceDebugPrintf("%s:read_last_block:0x%X\n", __FUNCTION__, res);
	}

	return res;
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args){

	if(args == NULL)
		return SCE_KERNEL_START_NO_RESIDENT;

	int res;
	AuthArg authArg;
	memcpy(&authArg, args, sizeof(authArg));

	if(argc != sizeof(AuthArg)){
		ksceDebugPrintf("Invalid args\n");

		res = -1;
		ksceKernelMemcpyKernelToUser((uintptr_t)authArg.res, &res, 4);

		return SCE_KERNEL_START_NO_RESIDENT;
	}

	switch(authArg.cmd){
	case 0:
		res = run_on_thread(sceUsSpkgAuthThread, argc, &authArg);
		break;
	case 1:
		res = run_on_thread(rootKeyGetThread, argc, &authArg);
		break;
	default:
		res = -1;
		break;
	}

	ksceKernelMemcpyKernelToUser((uintptr_t)authArg.res, &res, 4);

	return SCE_KERNEL_START_NO_RESIDENT;
}
