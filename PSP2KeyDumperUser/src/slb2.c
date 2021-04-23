/*
 * SCE SLB2 Reader
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2/kernel/clib.h>
#include <psp2/paf.h>
#include "slb2.h"

int sceSlb2InitializeContext(SceSlb2Context *pContext, Slb2ReadSector read){

	if(pContext == NULL || read == NULL)
		return -1;

	sce_paf_private_memset(pContext, 0, sizeof(*pContext));

	pContext->read = read;
	int res = pContext->read(0, &pContext->header, 1);

	if(res < 0){
		sceClibPrintf("%s:read sector : 0x%X\n", __FUNCTION__, res);
		return res;
	}

	if(sce_paf_private_memcmp(pContext->header.magic, "SLB2", 4) != 0){
		sceClibPrintf("magic:'%s'\n", pContext->header.magic);
		sce_paf_private_memset(pContext, 0, sizeof(*pContext));
		return -2;
	}

	if(pContext->header.version != 1){
		sce_paf_private_memset(pContext, 0, sizeof(*pContext));
		return -3;
	}

	return 0;
}

int sceSlb2Open(SceSlb2Context *pContext, const char *name){

	for(int i=0;i<pContext->header.file_count;i++){
		if(sce_paf_private_strcmp(name, pContext->header.entry[i].file_name) == 0){
			return (i << 1) | 1;
		}
	}

	return -1;
}

int sceSlb2Close(SceSlb2Context *pContext, int fd){

	if((fd >> 1) >= pContext->header.file_count)
		return -1;

	pContext->seek[(fd >> 1)] = 0;
	return 0;
}

int sceSlb2Read(SceSlb2Context *pContext, int fd, void *data, SceSize size){

	SceUInt32 index = fd >> 1;

	if(index >= pContext->header.file_count)
		return -1;

	if(pContext->seek[index] == size)
		return 0;

	if((pContext->seek[index] + size) > pContext->header.entry[index].size)
		size = pContext->header.entry[index].size - pContext->seek[index];

	pContext->read(pContext->header.entry[index].sector_pos + (pContext->seek[index] >> 9), data, size >> 9);

	pContext->seek[index] += size;

	return size;
}
