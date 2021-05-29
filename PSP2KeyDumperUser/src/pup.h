/*
 * SCE PUP Reader
 * Copyright (C) 2021, Princess of Sleeping
 */

#ifndef _PUP_H_
#define _PUP_H_

typedef struct ScePupHeader { // size is 0x80
	char magic[7];
	char unk_0x07;
	uint32_t package_version;
	uint32_t unk_0x0C;

	uint32_t image_version;
	uint32_t unk_0x14;
	uint32_t file_count;
	uint32_t unk_0x1C;

	uint64_t header_length;
	uint64_t package_length;

	uint32_t header_hash_version; // Must be 2
	uint32_t hmac_key_index;
	uint32_t unk_0x38;
	uint32_t pup_type;

	uint32_t unk_0x40;
	uint32_t unk_0x44;
	uint32_t unk_0x48;
	uint32_t unk_0x4C;

	uint32_t unk_0x50;
	uint32_t unk_0x54;
	uint32_t unk_0x58;
	uint32_t unk_0x5C;

	uint32_t unk_0x60;
	uint32_t unk_0x64;
	uint32_t unk_0x68;
	uint32_t unk_0x6C;

	uint32_t unk_0x70;
	uint32_t unk_0x74;
	uint32_t unk_0x78;
	uint32_t unk_0x7C;
} ScePupHeader;

typedef struct ScePupSegmentInfo { // size is 0x20
	SceUInt64 entry_id;
	SceUInt64 data_offset;
	SceUInt64 data_length;
	SceUInt64 unk_0x18;		// ex:2
} ScePupSegmentInfo;

typedef struct ScePupSignature {
	uint32_t index;
	uint32_t unk_0x04;
	char hash[0x20];		// Hmac-sha256?
	uint32_t unk_0x28;
	uint32_t unk_0x2C;
	uint32_t unk_0x30;
	uint32_t unk_0x34;
	uint32_t unk_0x38;
	uint32_t unk_0x3C;
} ScePupSignature;

typedef struct ScePupReadInfo {
	SceOff seek;
} ScePupReadInfo;

typedef struct ScePupContext {
	SceUID fd;
	ScePupHeader      *pHeader;
	ScePupSegmentInfo *pSegmentInfoList;
	ScePupSignature   *pSignatureList;
	ScePupReadInfo    *pReadInfo;
} ScePupContext;

void scePupPrintEntrys(const ScePupContext *pContext);

int scePupOpen(ScePupContext *pContext, const char *path);
int scePupClose(ScePupContext *pContext);

int scePupRead(ScePupContext *pContext, int entry_id, void *data, SceSize size);
int scePupReadBySpkgType(ScePupContext *pContext, int spkg_type, SceUInt64 spkg_part, void *data, SceSize size);

int scePupGetEntryIdBySpkgType(const ScePupContext *pContext, int spkg_type, SceUInt64 spkg_part, SceUInt64 *id);

#include "ref00d/self.h"

typedef struct SceSpkgHeader { // size is 0x80
	SceUInt32 version;
	SceUInt32 type;
	SceUInt32 flags;
	SceUInt32 unk_0x0C;

	SceUInt32 UpdateFwVersion;
	SceUInt32 unk_0x14;
	SceUInt64 decompressedSize;

	SceUInt64 decryptedSize;
	SceUInt32 unk_0x28;
	SceUInt32 platform; // 0x10000000 - Devkit/Prototype?, 0x20000000 - Testkit

	SceUInt64 unk_0x30;
	SceUInt64 unk_0x38;

	SceUInt64 unk_0x40; // 3 ?
	SceUInt64 unk_0x48; // 0x40 ?

	SceUInt64 Offset;
	SceUInt64 Size;

	SceUInt64 partIndex;
	SceUInt64 totalParts;

	SceUInt64 unk_0x70;
	SceUInt64 unk_0x78;
} SceSpkgHeader;

#endif /* _PUP_H_ */
