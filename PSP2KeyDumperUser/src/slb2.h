/*
 * SCE SLB2 Reader
 * Copyright (C) 2021, Princess of Sleeping
 */

#ifndef _SLB2_H_
#define _SLB2_H_

typedef struct SceSlb2Entry { // size is 0x30
	uint32_t sector_pos;
	uint32_t size;
	uint32_t unk_0x8;
	uint32_t unk_0xC;
	char file_name[0x20];
} __attribute__((packed)) SceSlb2Entry;

typedef struct SceSlb2Header { // size is 0x200
	char magic[4];
	SceInt32 version;
	SceSize  header_size;
	uint32_t file_count;
	uint32_t file_align;
	uint32_t unk[3];
	SceSlb2Entry entry[10];
} __attribute__((packed)) SceSlb2Header;

typedef int (* Slb2ReadSector)(SceUInt32 sector_pos, void *data, SceUInt32 sector_num);

typedef struct SceSlb2Context {
	SceSlb2Header  header;
	Slb2ReadSector read;
	SceUInt32 seek[10];
} __attribute__((packed)) SceSlb2Context;

int sceSlb2InitializeContext(SceSlb2Context *pContext, Slb2ReadSector read);

int sceSlb2Open(SceSlb2Context *pContext, const char *name);
int sceSlb2Close(SceSlb2Context *pContext, int fd);

int sceSlb2Read(SceSlb2Context *pContext, int fd, void *data, SceSize size);

#endif /* _SLB2_H_ */
