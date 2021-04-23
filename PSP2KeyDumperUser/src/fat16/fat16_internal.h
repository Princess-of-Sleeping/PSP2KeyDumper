/*
 * Easy FAT16 Library
 * Copyright (C) 2021, Princess of Sleeping
 */

#ifndef _FAT16_INTERNAL_H_
#define _FAT16_INTERNAL_H_

#include <stdint.h>

typedef int (* FatReadSectorFunc)(void *args, uint32_t start_sector, void *buf, uint32_t read_sector_num);
typedef int (* FatWriteSectorFunc)(void *args, uint32_t start_sector, const void *buf, uint32_t read_sector_num);

typedef struct FatReadCtx {
	int drive_len;
	FatReadSectorFunc fatReadSector;
	FatWriteSectorFunc fatWriteSector;
	int flags;
	void *pArgs;
	void *pWork;
	uint8_t *pFatTableLookupBuffer;
	uint32_t lookup_cached_clus;
	uint32_t root_ent_sector;
	uint32_t clus_size;
	uint32_t clus_shift;
	uint32_t SecPerClus;
} FatReadCtx;

typedef struct FatReadFd {
	uint32_t magic;
	FatReadCtx *ctx;
	uint32_t ent_sector;
	uint32_t clus_current;
	uint32_t file_size;
	uint32_t file_offset;
} FatReadFd;

#endif	/* _FAT16_INTERNAL_H_ */
