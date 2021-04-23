/*
 * SCE PUP Reader
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2/kernel/clib.h>
#include <psp2/io/fcntl.h>
#include <psp2/paf.h>
#include "pup.h"

void scePupPrintEntrys(const ScePupContext *pContext){
	for(int i=0;i<pContext->pHeader->file_count;i++){
		sceClibPrintf(
			"0x%04X:Xentry_id:0x%08llX data_offset:0x%08llX data_length:0x%08llX\n",
			i,
			pContext->pSegmentInfoList[i].entry_id,
			pContext->pSegmentInfoList[i].data_offset,
			pContext->pSegmentInfoList[i].data_length
		);
	}
}

int scePupOpen(ScePupContext *pContext, const char *path){

	SceUID fd;

	if(pContext == NULL)
		return -1;

	sceClibMemset(pContext, 0, sizeof(*pContext));
	pContext->fd = -1;

	fd = sceIoOpen(path, SCE_O_RDONLY, 0);
	if(fd < 0)
		return fd;

	pContext->fd = fd;

	ScePupHeader      *pHeader;
	ScePupSegmentInfo *pSegmentInfoList;
	ScePupSignature   *pSignatureList;
	ScePupReadInfo    *pReadInfo;

	pHeader = sce_paf_private_malloc(sizeof(*pHeader));
	if(pHeader == NULL){
		sceClibPrintf("Cannot allocate memory.\n");
		return -2;
	}

	pContext->pHeader = pHeader;

	int res;

	res = sceIoRead(fd, pHeader, sizeof(*pHeader));
	if(res != sizeof(*pHeader)){
		sceClibPrintf("Error:sceIoRead returns 0x%X\n", res);
		return -3;
	}

	// pHeader check


	if(pHeader->file_count == 0){
		sceClibPrintf("Error:not has pup entry\n");
		return -4;
	}


	pSegmentInfoList = sce_paf_private_malloc(sizeof(*pSegmentInfoList) * pHeader->file_count);
	if(pSegmentInfoList == NULL){
		sceClibPrintf("Cannot allocate memory.\n");
		return -2;
	}

	pContext->pSegmentInfoList = pSegmentInfoList;


	pSignatureList = sce_paf_private_malloc(sizeof(*pSignatureList) * pHeader->file_count);
	if(pSignatureList == NULL){
		sceClibPrintf("Cannot allocate memory.\n");
		return -2;
	}

	pContext->pSignatureList = pSignatureList;


	pReadInfo = sce_paf_private_malloc(sizeof(*pReadInfo) * pHeader->file_count);
	if(pReadInfo == NULL){
		sceClibPrintf("Cannot allocate memory.\n");
		return -2;
	}

	pContext->pReadInfo = pReadInfo;

	sceClibMemset(pReadInfo, 0, sizeof(*pReadInfo) * pHeader->file_count);



	res = sceIoRead(fd, pSegmentInfoList, sizeof(*pSegmentInfoList) * pHeader->file_count);
	if(res != (sizeof(*pSegmentInfoList) * pHeader->file_count)){
		sceClibPrintf("Error:sceIoRead returns 0x%X\n", res);
		return -3;
	}

	res = sceIoRead(fd, pSignatureList, sizeof(*pSignatureList) * pHeader->file_count);
	if(res != (sizeof(*pSignatureList) * pHeader->file_count)){
		sceClibPrintf("Error:sceIoRead returns 0x%X\n", res);
		return -3;
	}

	return 0;
}

int scePupClose(ScePupContext *pContext){

	if(pContext == NULL)
		return -1;

	if(pContext->fd > 0)
		sceIoClose(pContext->fd);

	if(pContext->pHeader != NULL)
		sce_paf_private_free(pContext->pHeader);

	if(pContext->pSegmentInfoList != NULL)
		sce_paf_private_free(pContext->pSegmentInfoList);

	if(pContext->pSignatureList != NULL)
		sce_paf_private_free(pContext->pSignatureList);

	if(pContext->pReadInfo != NULL)
		sce_paf_private_free(pContext->pReadInfo);

	sceClibMemset(pContext, 0, sizeof(*pContext));
	pContext->fd = -1;

	return 0;
}

int scePupGetSegmentIndexById(const ScePupContext *pContext, SceUInt32 id, SceUInt32 *pIndex){

	int res = -1;

	for(int i=0;i<pContext->pHeader->file_count;i++){
		if(pContext->pSegmentInfoList[i].entry_id == id){
			*pIndex = i;
			res = 0;
		}
	}

	return res;
}

int scePupRead(ScePupContext *pContext, int entry_id, void *data, SceSize size){

	if(pContext == NULL)
		return -1;

	int res;
	SceUInt32 index;

	res = scePupGetSegmentIndexById(pContext, entry_id, &index);
	if(res < 0){
		sceClibPrintf("%s:not found entry.\n", __FUNCTION__);
		return res;
	}

	ScePupSegmentInfo *pSegmentInfo = &pContext->pSegmentInfoList[index];
	ScePupReadInfo    *pReadInfo    = &pContext->pReadInfo[index];

	if(pReadInfo->seek == pSegmentInfo->data_length)
		return 0;

	if((pReadInfo->seek + size) > pSegmentInfo->data_length)
		size = (SceSize)(pSegmentInfo->data_length - pReadInfo->seek);

	res = sceIoPread(pContext->fd, data, size, pSegmentInfo->data_offset + pReadInfo->seek);

	pReadInfo->seek += size;

	return res;
}

int scePupLseek(ScePupContext *pContext, int entry_id, SceOff offset){
	return -1;
}

int scePupGetSegmentSizeById(ScePupContext *pContext, SceUInt32 id, SceInt64 *pSize){
	return -1;
}

int scePupGetEntryIdBySpkgType(const ScePupContext *pContext, int spkg_type, SceUInt64 spkg_part, SceUInt64 *id){

	int res;
	cf_header header;
	SceSpkgHeader spkg_header;

	for(int i=0;i<pContext->pHeader->file_count;i++){
		if(pContext->pSegmentInfoList[i].entry_id >= 0x220 && pContext->pSegmentInfoList[i].entry_id < 0x400){

			ScePupSegmentInfo *pSegmentInfo = &pContext->pSegmentInfoList[i];

			res = sceIoPread(pContext->fd, &header, sizeof(header), pSegmentInfo->data_offset);
			if(res != sizeof(header)){
				if(res >= 0)
					res = -2;

				return res;
			}

			res = sceIoPread(pContext->fd, &spkg_header, sizeof(spkg_header), pSegmentInfo->data_offset + header.m_file_offset);
			if(res != sizeof(spkg_header)){
				if(res >= 0)
					res = -2;

				sceClibPrintf("%s:error. 0x%X\n", __FUNCTION__, i);

				return res;
			}

			if(spkg_header.type == spkg_type && spkg_header.partIndex == spkg_part){
				*id = pContext->pSegmentInfoList[i].entry_id;
				return 0;
			}
		}
	}

	return -1;
}

int scePupReadBySpkgType(ScePupContext *pContext, int spkg_type, SceUInt64 spkg_part, void *data, SceSize size){

	int res;
	SceUInt64 id = 0;

	res = scePupGetEntryIdBySpkgType(pContext, spkg_type, spkg_part, &id);
	if(res < 0)
		return res;

	res = scePupRead(pContext, id, data, size);

	return res;
}
