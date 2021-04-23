/*
 * Easy FAT16 Library
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2/kernel/clib.h>
#include <psp2/paf.h>
#include "fat16.h"
#include "fat16_internal.h"
#include "fat16_api.h"

int fat16_get_file_name(char *dst, void *ptr){

	char *pfile_name = dst;
	EntryFileName_t *entry_file_name = ptr;

	if((entry_file_name->LDIR_Ord & 0x40) == 0)
		return -1;

	if((entry_file_name->LDIR_Ord & ~0x40) > 0x14)
		return -1;

	int ent_name_num = entry_file_name->LDIR_Ord & ~0x40;
	int res = ent_name_num;

	entry_file_name = (EntryFileName_t *)(((uintptr_t)ptr) + (sizeof(EntryFileName_t) * (ent_name_num - 1)));

	while(ent_name_num != 0){

#define FAT16_CPY_FNAME(count, ptr)          \
		for(int i=0;i<count;i++){    \
			if(ptr[i] >= 0x100){ \
				*(uint16_t *)(pfile_name) = ptr[i]; \
				pfile_name += 2;                    \
			}else{                                      \
				*(uint8_t  *)(pfile_name) = ptr[i] & 0xFF; \
				pfile_name += 1;                           \
			}                                                  \
		}

		FAT16_CPY_FNAME(5, entry_file_name->LDIR_Name1);
		FAT16_CPY_FNAME(6, entry_file_name->LDIR_Name2);
		FAT16_CPY_FNAME(2, entry_file_name->LDIR_Name3);

		entry_file_name = (EntryFileName_t *)(((uintptr_t)entry_file_name) - sizeof(EntryFileName_t));
		ent_name_num--;
	}

	return res;
}

int fat16_get_file_name_short(char *dst, void *ptr){

	EntryInfo_t *entry_file_name = ptr;
	int idx = 0;

	for(int i=0;i<11;i++){
		if(entry_file_name->DIR_Name[i] != ' '){
			dst[idx++] = entry_file_name->DIR_Name[i];
		}
	}

	dst[idx++] = 0;

	return 0;
}

int fatGetClusterShift(uint32_t clus_size){

	int res = 0;

	while((clus_size & (1 << res)) == 0){
		res++;
	}

	return res;
}

int fatGetNextCluster(FatReadCtx *ctx, uint16_t Clus){

	uint32_t sector = (0x2 + ((Clus * 2) >> 9));
	uint32_t offset = ((Clus * 2) & 0x1FF);

	if(ctx->lookup_cached_clus != Clus){
		ctx->lookup_cached_clus = Clus;
		ctx->fatReadSector(ctx->pArgs, sector, ctx->pFatTableLookupBuffer, 1);
	}

	return *(uint16_t *)(&ctx->pFatTableLookupBuffer[offset]);
}

int fatGetEntryByName(FatReadCtx *ctx, uint32_t ent_sector, const char *name, EntryInfo_t *info){

	char fname[0x200];
	int current_pos = 0;

	if(ctx->pWork == NULL){
		sceClibPrintf("%s:ctx->pWork is NULL\n", __FUNCTION__);
	}

	ctx->fatReadSector(ctx->pArgs, ctx->root_ent_sector + ent_sector, ctx->pWork, 4);

	EntryFileName_t *entry_file_name = (EntryFileName_t *)ctx->pWork;

	// sceClibPrintf("fatGetEntryByName 0x%08X %s\n", ent_sector, name);

	uint16_t clus;
	clus = ((ent_sector - 0x20) >> ctx->clus_shift) + 2;

	while(entry_file_name->LDIR_Ord != 0){
		if(entry_file_name->LDIR_Ord == 0xE5 || entry_file_name->LDIR_Ord == '.'){
			current_pos += sizeof(EntryFileName_t);

			if(current_pos == 0x400){
				ent_sector += 2;

				if((ent_sector & (ctx->SecPerClus - 1)) == 0){
					clus = fatGetNextCluster(ctx, clus);
					if(clus == 0xFFFF)
						return -2;
					ent_sector = (((clus - 2) << ctx->clus_shift) + 0x20);
					ctx->fatReadSector(ctx->pArgs, ctx->root_ent_sector + ent_sector, ctx->pWork, 4);
				}else if((ent_sector & (ctx->SecPerClus - 1)) > (ctx->SecPerClus - 4)){
					ctx->fatReadSector(ctx->pArgs, ctx->root_ent_sector + ent_sector, ctx->pWork, 2);

					uint32_t tmp_clus = fatGetNextCluster(ctx, clus);
					if(tmp_clus != 0xFFFF){
						ctx->fatReadSector(
							ctx->pArgs,
							ctx->root_ent_sector
							+ (((tmp_clus - 2) << ctx->clus_shift) + 0x20),
							ctx->pWork + 0x400,
							2
						);
					}else{
						sceClibMemset(ctx->pWork + 0x400, 0, 0x400);
					}
				}else{
					ctx->fatReadSector(ctx->pArgs, ctx->root_ent_sector + ent_sector, ctx->pWork, 4);
				}

				current_pos -= 0x400;
			}
		}else{
			if(((EntryFileName_t *)(ctx->pWork + current_pos))->LDIR_Attr == 0xF){
				int ent_size = entry_file_name->LDIR_Ord & ~0x40;
				if((entry_file_name->LDIR_Ord & 0x40) == 0)
					return -1;

				if(ent_size > 0x14)
					return -1;
			}

			if(current_pos >= 0x400){
				ent_sector += 2;

				if((ent_sector & (ctx->SecPerClus - 1)) == 0){
					clus = fatGetNextCluster(ctx, clus);
					if(clus == 0xFFFF)
						return -2;
					ent_sector = (((clus - 2) << ctx->clus_shift) + 0x20);
					ctx->fatReadSector(ctx->pArgs, ctx->root_ent_sector + ent_sector, ctx->pWork, 4);
				}else if((ent_sector & (ctx->SecPerClus - 1)) > (ctx->SecPerClus - 4)){
					ctx->fatReadSector(ctx->pArgs, ctx->root_ent_sector + ent_sector, ctx->pWork, 2);

					uint32_t tmp_clus = fatGetNextCluster(ctx, clus);
					if(tmp_clus != 0xFFFF){
						ctx->fatReadSector(
							ctx->pArgs,
							ctx->root_ent_sector
							+ (((tmp_clus - 2) << ctx->clus_shift) + 0x20),
							ctx->pWork + 0x400,
							2
						);
					}else{
						sceClibMemset(ctx->pWork + 0x400, 0, 0x400);
					}
				}else{
					ctx->fatReadSector(ctx->pArgs, ctx->root_ent_sector + ent_sector, ctx->pWork, 4);
				}

				current_pos -= 0x400;
			}

			int res;

			if(((EntryFileName_t *)(ctx->pWork + current_pos))->LDIR_Attr == 0xF){
				res = fat16_get_file_name(fname, ctx->pWork + current_pos);
				if(res < 0){
					// sceClibPrintf("[%-7s] %s:%s 0x%X\n", "error", __FUNCTION__, "fat16_get_file_name", res);
					return res;
				}
			}else{
				res = fat16_get_file_name_short(fname, ctx->pWork + current_pos);
			}

			if(sceClibStrncmp(name, fname, 0x100) == 0){
				sceClibMemcpy(info, ctx->pWork + current_pos + (res * sizeof(EntryFileName_t)), sizeof(EntryInfo_t));
				return 0;
			}

			current_pos += ((res + 1) * sizeof(EntryFileName_t));
		}

		entry_file_name = (EntryFileName_t *)(ctx->pWork + current_pos);
	}

	return -2;
}

const char *my_strchr(const char *path, char ch){

	while(*path != ch && *path != 0){
		path++;
	}

	if(*path != 0)
		return path;

	return NULL;
}

int fatGetEntry(FatReadCtx *ctx, const char *path, uint32_t sector_pos, EntryInfo_t *ent){

	int res;
	char ent_name[0x100];
	EntryInfo_t info;

	const char *s = my_strchr(path, '/');
	if(s != NULL){
		ent_name[(s - path)] = 0;
		sceClibStrncpy(ent_name, path, (SceSize)(s - path));

		res = fatGetEntryByName(ctx, sector_pos, ent_name, &info);
		if(res < 0)
			return res;

		if((info.DIR_Attr & 0x10) == 0)
			return -1;

		res = fatGetEntry(ctx, &s[1], ((info.DIR_FstClusLO - 2) << ctx->clus_shift) + 0x20, ent);
		if(res < 0){
			return res;
		}
	}else{
		res = fatGetEntryByName(ctx, sector_pos, path, ent);
		if(res < 0)
			return res;

		if((ent->DIR_Attr & 0x10) != 0)
			return -1;
	}

	return 0;
}

int fatInitCtx(FatReadCtx *ctx, int flags, const void *args, int args_size, FatReadSectorFunc fatReadSectorFunc, FatWriteSectorFunc fatWriteSectorFunc){

	FAT16_t fat16_tmp;

	if((flags & FAT16_PART_RERMISSION_RD) == 0){
		sceClibPrintf("%s:not has read permission\n", __FUNCTION__);
		return -1;
	}

	if(fatReadSectorFunc == NULL){
		sceClibPrintf("%s:fatReadSectorFunc is NULL\n", __FUNCTION__);
		return -1;
	}

	if((flags & FAT16_PART_RERMISSION_RW) != 0 && fatWriteSectorFunc == NULL){
		sceClibPrintf("%s:fatWriteSectorFunc is NULL\n", __FUNCTION__);
		return -1;
	}

	ctx->fatReadSector  = fatReadSectorFunc;
	ctx->fatWriteSector = fatWriteSectorFunc;
	ctx->flags          = flags;

	if(ctx->pArgs != NULL && args_size != 0){
		ctx->pArgs = sce_paf_memalign(4, args_size);
		sceClibMemcpy(ctx->pArgs, args, args_size);
	}

	ctx->fatReadSector(ctx->pArgs, 0, &fat16_tmp, 1);

	if(fat16_tmp.bpb.BPB_NumFATs != 2){
		sceClibPrintf("%s:NumFATs != 2\n", __FUNCTION__);
		return -1;
	}

	if(fat16_tmp.bpb.BPB_BytsPerSec != 0x200){
		sceClibPrintf("%s:Sector size is not 0x200\n", __FUNCTION__);
		return -1;
	}

	if(fat16_tmp.bpb.BPB_SecPerClus < 8){
		sceClibPrintf("%s:SecPerClus < 8\n", __FUNCTION__);
		return -1;
	}

	if(sceClibStrncmp(fat16_tmp.fat16_base.BS_FilSysType, "FAT16   ", 8) != 0){
		sceClibPrintf("%s:not FAT16 name\n", __FUNCTION__);
		return -1;
	}

	ctx->pWork = sce_paf_memalign(0x40, 0x800);
	if(ctx->pWork == NULL){
		sceClibPrintf("%s:ctx->pWork is NULL\n", __FUNCTION__);
	}

	ctx->pFatTableLookupBuffer = sce_paf_memalign(0x40, 0x200);
	ctx->lookup_cached_clus    = 0xFFFF;
	if(ctx->pFatTableLookupBuffer == NULL){
		sceClibPrintf("%s:ctx->pFatTableLookupBuffer is NULL\n", __FUNCTION__);
	}

	ctx->root_ent_sector = fat16_tmp.bpb.BPB_RsvdSecCnt + (fat16_tmp.bpb.BPB_FATSz16 * fat16_tmp.bpb.BPB_NumFATs);

	ctx->clus_size  = fat16_tmp.bpb.BPB_SecPerClus * fat16_tmp.bpb.BPB_BytsPerSec;
	ctx->clus_shift = fatGetClusterShift(ctx->clus_size) - 9;
	ctx->SecPerClus = fat16_tmp.bpb.BPB_SecPerClus;

	return 0;
}


typedef struct FatPartCtxTree {
	struct FatPartCtxTree *next;
	FatReadCtx *ctx;
	const char *drive;
	int drive_len;
} FatPartCtxTree;


#define DACR_OFF(stmt)                 \
do {                                   \
    unsigned prev_dacr;                \
    __asm__ volatile(                  \
        "mrc p15, 0, %0, c3, c0, 0 \n" \
        : "=r" (prev_dacr)             \
    );                                 \
    __asm__ volatile(                  \
        "mcr p15, 0, %0, c3, c0, 0 \n" \
        : : "r" (0xFFFF0000)           \
    );                                 \
    stmt;                              \
    __asm__ volatile(                  \
        "mcr p15, 0, %0, c3, c0, 0 \n" \
        : : "r" (prev_dacr)            \
    );                                 \
} while (0)

static FatPartCtxTree *top_tree = NULL;

int fatAddPartCtx(const char *drive, int flags, const void *args, int args_size, FatReadSectorFunc fatReadSectorFunc, FatWriteSectorFunc fatWriteSectorFunc){

	int res;

	int drive_len = sceClibStrnlen(drive, 6);
	if(drive[drive_len - 1] != ':')
		return -1;

	FatPartCtxTree *part_ctx = sce_paf_memalign(4, sizeof(FatPartCtxTree));

	part_ctx->next = top_tree;
	part_ctx->ctx = sce_paf_memalign(4, sizeof(FatReadCtx));

	res = fatInitCtx(part_ctx->ctx, flags, args, args_size, fatReadSectorFunc, fatWriteSectorFunc);
	if(res < 0){
		sceClibPrintf("%s:fatInitCtx failed 0x%X\n", __FUNCTION__, res);
		return res;
	}

	char *tmp_drive = sce_paf_memalign(4, drive_len + 1);
	sceClibMemcpy(tmp_drive, drive, drive_len);
	tmp_drive[drive_len] = 0;

	part_ctx->drive          = tmp_drive;
	part_ctx->drive_len      = drive_len;
	part_ctx->ctx->drive_len = drive_len;

	// DACR_OFF(top_tree = part_ctx);
	top_tree = part_ctx;

	return 0;
}

FatReadCtx *fatSearchReadCtx(const char *s){

	FatPartCtxTree *local_tree = top_tree;

	while(local_tree != NULL){
		if(sceClibStrncmp(s, local_tree->drive, local_tree->drive_len) == 0){
			return local_tree->ctx;
		}
		local_tree = local_tree->next;
	}

	return NULL;
}


int fatIoOpen(const char *path, int flags, int mode){

	int res;
	EntryInfo_t info;

	FatReadCtx *ctx = fatSearchReadCtx(path);
	if(ctx == NULL)
		return -2;

	path = &(path[ctx->drive_len]);

	res = fatGetEntry(ctx, (path[0] != '/') ? path : &path[1], 0, &info);
	if(res < 0)
		return res;

	FatReadFd *pFdInternal = sce_paf_memalign(8, sizeof(FatReadFd));

	pFdInternal->magic        = 0x41516171;
	pFdInternal->ctx          = ctx;
	pFdInternal->ent_sector   = ctx->root_ent_sector + (((info.DIR_FstClusLO - 2) << ctx->clus_shift) + 0x20);
	pFdInternal->clus_current = info.DIR_FstClusLO;
	pFdInternal->file_size    = info.DIR_FileSize;
	pFdInternal->file_offset  = 0;

	// sceClibPrintf("pFd->ent_sector:0x%X\n", pFdInternal->ent_sector);
	// sceClibPrintf("pFd->file_size :0x%X\n", pFdInternal->file_size);

	// sceClibPrintf("pFdInternal:0x%X\n", pFdInternal);
	// sceClibPrintf("fd:0x%X\n", ((((uintptr_t)pFdInternal) >> 2) | 1) ^ 0x12348);

	return ((((uintptr_t)pFdInternal) >> 2) | 1) ^ 0x12348;
}

int fatIoClose(int fd){

	FatReadFd *pFd = (FatReadFd *)(((fd ^ 0x12348) & ~1) << 2);

	// sceClibPrintf("pFdInternal:0x%X\n", pFd);
	// sceClibPrintf("fd:0x%X\n", fd);

	if(pFd->magic != 0x41516171)
		return -1;

	sceClibMemset(pFd, 0, sizeof(*pFd));

	sce_paf_private_free(pFd);

	return 0;
}

int fatIoRead(int fd, void *data, uint32_t size){

	FatReadFd *pFd = (FatReadFd *)(((fd ^ 0x12348) & ~1) << 2);

	if(pFd->magic != 0x41516171)
		return -1;

	if((pFd->file_size - pFd->file_offset) == 0)
		return 0;

	if((pFd->file_size - pFd->file_offset) < size)
		size = pFd->file_size - pFd->file_offset;

	void *data_x = data;
	char tmp[0x200];
	SceSize cpy_len;

	if((pFd->file_offset & 0x1FF) != 0){

		pFd->ctx->fatReadSector(
			pFd->ctx->pArgs,
			pFd->ctx->root_ent_sector
			+ (((pFd->clus_current - 2) << pFd->ctx->clus_shift) + 0x20)
			+ ((pFd->file_offset & (pFd->ctx->clus_size - 0x200)) >> 9),
			tmp,
			1
		);

		cpy_len = 0x200 - (pFd->file_offset & 0x1FF);
		if(cpy_len > size)
			cpy_len = size;

		sceClibMemcpy(data, tmp + (pFd->file_offset & 0x1FF), cpy_len);

		pFd->file_offset += cpy_len; data += cpy_len; size -= cpy_len;

		if((pFd->file_offset & (pFd->ctx->clus_size - 1)) == 0){
			pFd->clus_current = fatGetNextCluster(pFd->ctx, pFd->clus_current);
		}
	}

	if((size & ~0x1FF) != 0){

		if((pFd->file_offset & (pFd->ctx->clus_size - 0x200)) != 0){

			cpy_len = pFd->ctx->clus_size - (pFd->file_offset & (pFd->ctx->clus_size - 0x200));

			if(cpy_len > (size & ~0x1FF))
				cpy_len = (size & ~0x1FF);

			pFd->ctx->fatReadSector(
				pFd->ctx->pArgs,
				pFd->ctx->root_ent_sector
				+ (((pFd->clus_current - 2) << pFd->ctx->clus_shift) + 0x20)
				+ ((pFd->file_offset & (pFd->ctx->clus_size - 0x200)) >> 9),
				data,
				cpy_len >> 9
			);

			pFd->file_offset += cpy_len; data += cpy_len; size -= cpy_len;

			if((pFd->file_offset & (pFd->ctx->clus_size - 1)) == 0)
				pFd->clus_current = fatGetNextCluster(pFd->ctx, pFd->clus_current);
		}
/*
		while(size >= 0x20000 && 0){ // Experimental

			int read_clus_num   = 1;
			int readed_size     = pFd->ctx->clus_size;
			int read_start_clus = pFd->clus_current;

			while(fatGetNextCluster(pFd->ctx, pFd->clus_current) == (pFd->clus_current + 1) && readed_size < 0x20000){
				read_clus_num++;
				readed_size += pFd->ctx->clus_size;
				pFd->clus_current = fatGetNextCluster(pFd->ctx, pFd->clus_current);
			}

			pFd->ctx->fatReadSector(
				pFd->ctx->pArgs,
				pFd->ctx->root_ent_sector
				+ (((read_start_clus - 2) << pFd->ctx->clus_shift) + 0x20),
				data,
				pFd->ctx->SecPerClus * read_clus_num
			);

			pFd->clus_current = fatGetNextCluster(pFd->ctx, pFd->clus_current);
			pFd->file_offset += readed_size; data += readed_size; size -= readed_size;
		}
*/
		while(size >= pFd->ctx->clus_size){
			pFd->ctx->fatReadSector(
				pFd->ctx->pArgs,
				pFd->ctx->root_ent_sector
				+ (((pFd->clus_current - 2) << pFd->ctx->clus_shift) + 0x20),
				data,
				pFd->ctx->SecPerClus
			);

			pFd->clus_current = fatGetNextCluster(pFd->ctx, pFd->clus_current);
			pFd->file_offset += pFd->ctx->clus_size; data += pFd->ctx->clus_size; size -= pFd->ctx->clus_size;
		}

		while(size >= 0x200){
			pFd->ctx->fatReadSector(
				pFd->ctx->pArgs,
				pFd->ctx->root_ent_sector
				+ (((pFd->clus_current - 2) << pFd->ctx->clus_shift) + 0x20)
				+ ((pFd->file_offset & (pFd->ctx->clus_size - 0x200)) >> 9),
				data,
				1
			);

			pFd->file_offset += 0x200; data += 0x200; size -= 0x200;
		}
	}

	if((size & 0x1FF) != 0){
		pFd->ctx->fatReadSector(
			pFd->ctx->pArgs,
			pFd->ctx->root_ent_sector
			+ (((pFd->clus_current - 2) << pFd->ctx->clus_shift) + 0x20)
			+ ((pFd->file_offset & (pFd->ctx->clus_size - 0x200)) >> 9),
			tmp,
			1
		);

		sceClibMemcpy(data, tmp + (pFd->file_offset & 0x1FF), (size & 0x1FF));
		pFd->file_offset += (size & 0x1FF); data += (size & 0x1FF); size -= (size & 0x1FF);
	}

	return data - data_x;
}

int fatIoWriteLimited(int fd, void *data, uint32_t size){

	FatReadFd *pFd = (FatReadFd *)(((fd ^ 0x12348) & ~1) << 2);

	if(pFd->magic != 0x41516171)
		return -1;

	if((pFd->file_size - pFd->file_offset) == 0)
		return 0;

	if((pFd->file_size - pFd->file_offset) < size)
		size = pFd->file_size - pFd->file_offset;

	void *data_x = data;
	char tmp[0x200];
	SceSize cpy_len;

	if((pFd->file_offset & 0x1FF) != 0){

		pFd->ctx->fatReadSector(
			pFd->ctx->pArgs,
			pFd->ctx->root_ent_sector
			+ (((pFd->clus_current - 2) << pFd->ctx->clus_shift) + 0x20)
			+ ((pFd->file_offset & (pFd->ctx->clus_size - 0x200)) >> 9),
			tmp,
			1
		);

		cpy_len = 0x200 - (pFd->file_offset & 0x1FF);
		if(cpy_len > size)
			cpy_len = size;

		sceClibMemcpy(tmp + (pFd->file_offset & 0x1FF), data, cpy_len);

		pFd->ctx->fatWriteSector(
			pFd->ctx->pArgs,
			pFd->ctx->root_ent_sector
			+ (((pFd->clus_current - 2) << pFd->ctx->clus_shift) + 0x20)
			+ ((pFd->file_offset & (pFd->ctx->clus_size - 0x200)) >> 9),
			tmp,
			1
		);

		pFd->file_offset += cpy_len; data += cpy_len; size -= cpy_len;

		if((pFd->file_offset & (pFd->ctx->clus_size - 1)) == 0){
			pFd->clus_current = fatGetNextCluster(pFd->ctx, pFd->clus_current);
		}
	}

	if((size & ~0x1FF) != 0){

		if((pFd->file_offset & (pFd->ctx->clus_size - 0x200)) != 0){

			cpy_len = pFd->ctx->clus_size - (pFd->file_offset & (pFd->ctx->clus_size - 0x200));

			if(cpy_len > (size & ~0x1FF))
				cpy_len = (size & ~0x1FF);

			pFd->ctx->fatWriteSector(
				pFd->ctx->pArgs,
				pFd->ctx->root_ent_sector
				+ (((pFd->clus_current - 2) << pFd->ctx->clus_shift) + 0x20)
				+ ((pFd->file_offset & (pFd->ctx->clus_size - 0x200)) >> 9),
				data,
				cpy_len >> 9
			);

			pFd->file_offset += cpy_len; data += cpy_len; size -= cpy_len;

			if((pFd->file_offset & (pFd->ctx->clus_size - 1)) == 0)
				pFd->clus_current = fatGetNextCluster(pFd->ctx, pFd->clus_current);
		}

		while(size >= pFd->ctx->clus_size){
			pFd->ctx->fatWriteSector(
				pFd->ctx->pArgs,
				pFd->ctx->root_ent_sector
				+ (((pFd->clus_current - 2) << pFd->ctx->clus_shift) + 0x20),
				data,
				pFd->ctx->SecPerClus
			);

			pFd->clus_current = fatGetNextCluster(pFd->ctx, pFd->clus_current);
			pFd->file_offset += pFd->ctx->clus_size; data += pFd->ctx->clus_size; size -= pFd->ctx->clus_size;
		}

		while(size >= 0x200){
			pFd->ctx->fatWriteSector(
				pFd->ctx->pArgs,
				pFd->ctx->root_ent_sector
				+ (((pFd->clus_current - 2) << pFd->ctx->clus_shift) + 0x20)
				+ ((pFd->file_offset & (pFd->ctx->clus_size - 0x200)) >> 9),
				data,
				1
			);

			pFd->file_offset += 0x200; data += 0x200; size -= 0x200;
		}
	}

	if((size & 0x1FF) != 0){
		pFd->ctx->fatReadSector(
			pFd->ctx->pArgs,
			pFd->ctx->root_ent_sector
			+ (((pFd->clus_current - 2) << pFd->ctx->clus_shift) + 0x20)
			+ ((pFd->file_offset & (pFd->ctx->clus_size - 0x200)) >> 9),
			tmp,
			1
		);

		sceClibMemcpy(tmp + (pFd->file_offset & 0x1FF), data, (size & 0x1FF));

		pFd->ctx->fatWriteSector(
			pFd->ctx->pArgs,
			pFd->ctx->root_ent_sector
			+ (((pFd->clus_current - 2) << pFd->ctx->clus_shift) + 0x20)
			+ ((pFd->file_offset & (pFd->ctx->clus_size - 0x200)) >> 9),
			tmp,
			1
		);

		pFd->file_offset += (size & 0x1FF); data += (size & 0x1FF); size -= (size & 0x1FF);
	}

	return data - data_x;
}

typedef enum SceIoSeekMode {
	SCE_SEEK_SET,   //!< Starts from the begin of the file
	SCE_SEEK_CUR,   //!< Starts from current position
	SCE_SEEK_END    //!< Starts from the end of the file
} SceIoSeekMode;

int fatIoLseek(int fd, int offset, int whence){

	FatReadFd *pFd = (FatReadFd *)(((fd ^ 0x12348) & ~1) << 2);

	if(pFd->magic != 0x41516171)
		return -1;

	int clus = (((pFd->ent_sector - 0x20) - pFd->ctx->root_ent_sector) >> pFd->ctx->clus_shift) + 2;
	int offset_tmp = 0;

	if(whence == SCE_SEEK_SET){

		if(pFd->file_size < (uint32_t)offset)
			return -1;

		offset_tmp = offset;

	}else if(whence == SCE_SEEK_CUR){

		if(offset >= 0){
			if((pFd->file_size - pFd->file_offset) < (uint32_t)offset)
				return -1;
		}else{
			if(pFd->file_offset < (uint32_t)offset)
				return -1;
		}

		offset_tmp = pFd->file_offset + offset;

	}else if(whence == SCE_SEEK_END){
		return -1; // not supported yet
	}

	pFd->file_offset = 0;

	while((offset_tmp & ~(pFd->ctx->clus_size - 1)) != pFd->file_offset){
		clus = fatGetNextCluster(pFd->ctx, clus);
		pFd->file_offset += pFd->ctx->clus_size;
	}

	pFd->file_offset += (offset_tmp & (pFd->ctx->clus_size - 1));
	pFd->clus_current = clus;

	return offset_tmp;
}
