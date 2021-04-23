/*
 * reF00D
 * Copyright (C) 2021, FAPS TEAM
 */

#include <psp2/kernel/threadmgr.h>
#include <psp2/kernel/clib.h>
#include <psp2/paf.h>
#include "self.h"
#include "elf.h"
#include "ref00d_types.h"
#include "ref00d_utils.h"
#include "ref00d_kprx_auth.h"

int module_get_offset(SceUID pid, SceUID modid, int segidx, uint32_t offset, uintptr_t *dst);

int kscePmMgrGetProductMode(uint8_t *res);

typedef struct SceNpDrmRsaKey {
	const void *n;
	const void *k; // e/d
} SceNpDrmRsaKey;

/* ================================ data section ================================ */

char *ref00d_private_header;
char ref00d_private_iv[0x10];

SceUID semaid;

int is_auth_success, currentKey;

SceSelfAuthHeaderInfo  *pHeaderInfo;
SceSelfAuthSegmentInfo *pSegmentInfo;

void *pKeyBase;

SceKprxAuthKey *g_key_info;

/* ================================ data section ================================ */

#define memcpy(dst, src, len) sceClibMemcpy(dst, src, len)
#define memset(dst, ch, len) sceClibMemset(dst, ch, len)
#define ksceDebugPrintf sceClibPrintf

#define ksceKernelWaitSema sceKernelWaitSema
#define ksceKernelSignalSema sceKernelSignalSema
#define ksceKernelCreateSema sceKernelCreateSema

const unsigned char key_seed[] = {
	0x4D, 0xE9, 0xF0, 0x27, 0x67, 0x73, 0x44, 0x5B, 0x76, 0x9D, 0xE8, 0xC8, 0x5A, 0x90, 0x61, 0xA2,
	0x19, 0x29, 0x6F, 0xC2, 0x8B, 0xEB, 0x2D, 0x87, 0x9A, 0xFD, 0x56, 0xCC, 0x53, 0x7E, 0xE0, 0x58
};

const unsigned char iv_seed[] = {
	0x43, 0x35, 0xAB, 0x3D, 0x40, 0xB2, 0x81, 0x7A, 0xA6, 0xEC, 0x46, 0xF3, 0x47, 0xFF, 0x63, 0x3B
};


typedef struct SceDmac5EncdecCtx {
	const void *src;
	void       *dst;
	SceSize     size;
	const void *key;
	SceSize     key_size; // (int bits)
	void       *iv;
} SceDmac5EncdecCtx;

int sceSblDmac5EncDec(SceDmac5EncdecCtx *ctx, int command);

int ref00dAesCbcDecrypt(const void *src, void *dst, int length, const void *key, SceSize keysize, void *iv){

	int cmd = 0;
	SceDmac5EncdecCtx ctx;

	ctx.src      = src;
	ctx.dst      = dst;
	ctx.size     = length;
	ctx.key      = key;
	ctx.iv       = iv;
	ctx.key_size = keysize;

	if((keysize >> 3) == 0x10){
		cmd = 0x100;
	}else if((keysize >> 3) == 0x18){
		cmd = 0x200;
	}else if((keysize >> 3) == 0x20){
		cmd = 0x300;
	}

	return sceSblDmac5EncDec(&ctx, 0xA | cmd);
}

int ksceSblDmac5AesCbcDec(const void *src, void *dst, SceSize size, const void *key, SceSize key_size, void *iv, int mask_enable){
	return ref00dAesCbcDecrypt(src, dst, size, key, key_size, iv);
}

int ksceSblDmac5AesCtrDec(const void *src, void *dst, SceSize size, const void *key, SceSize key_size, void *iv, int mask_enable){

	int cmd = 0;
	SceDmac5EncdecCtx ctx;

	ctx.src      = src;
	ctx.dst      = dst;
	ctx.size     = size;
	ctx.key      = key;
	ctx.iv       = iv;
	ctx.key_size = key_size;

	if((key_size >> 3) == 0x10){
		cmd = 0x100;
	}else if((key_size >> 3) == 0x18){
		cmd = 0x200;
	}else if((key_size >> 3) == 0x20){
		cmd = 0x300;
	}

	return sceSblDmac5EncDec(&ctx, 0x21 | cmd);
}

int ref00d_kprx_auth_initialization(void){

	semaid = ksceKernelCreateSema("ReF00DSema", 0, 1, 1, NULL);
	if(semaid < 0)
		return semaid;

	g_key_info = sce_paf_memalign(0x40, sizeof(*g_key_info));
	if(g_key_info == NULL){
		printf("%s:sce_paf_memalign failed\n", __FUNCTION__);
		return -1;
	}

	void *memptr = sce_paf_memalign(0x40, 0x1000);
	if(memptr == NULL){
		printf("%s:sce_paf_memalign failed\n", __FUNCTION__);
		return -1;
	}

	ref00d_private_header = (char *)(((uintptr_t)memptr + 0x3F) & ~0x3F);

	return 0;
}

int remove_npdrm_personalize(cf_header *cf_hdr, const void *key, const void *klicensee){

	char klicensee_dec[0x10];
	char iv[0x20];

	void *decrypt_point = &ref00d_private_header[sizeof(cf_header) + cf_hdr->m_ext_header_size];

	memset(&iv, 0, sizeof(iv));

	// klicensee to metadata decrypt key
	ksceSblDmac5AesCbcDec(klicensee, &klicensee_dec, 0x10, key, 0x80, &iv, 1);

	// decrypt metadata
	ksceSblDmac5AesCbcDec(decrypt_point, decrypt_point, sizeof(SceSelfAuthHeaderKey), klicensee_dec, 0x80, &iv[0x10], 1);

	return 0;
}

int decrypt_certified_personalize(const SceKprxAuthKey *key_info){

	SceSelfAuthHeaderKey *pHeaderKey;

	cf_header *cf_hdr = (cf_header *)ref00d_private_header;
	void *decrypt_point;
	char rw_iv[0x10];
	char ref00d_private_header_iv[0x10];
	int res;

	memcpy(rw_iv, key_info->iv, sizeof(rw_iv));

	decrypt_point = &ref00d_private_header[sizeof(cf_header) + cf_hdr->m_ext_header_size];

	res = ksceSblDmac5AesCbcDec(decrypt_point, decrypt_point, sizeof(SceSelfAuthHeaderKey), key_info->key, 0x100, rw_iv, 1);
	if(res < 0){
		ksceDebugPrintf("%s:ksceSblDmac5AesCbcDec failed : 0x%X\n", __FUNCTION__, res);
		return res;
	}

	pHeaderKey = decrypt_point;
	decrypt_point += sizeof(SceSelfAuthHeaderKey);

	memcpy(ref00d_private_header_iv, pHeaderKey->iv, 0x10);

	SceSize DecryptSize = cf_hdr->m_header_length - (sizeof(cf_header) + cf_hdr->m_ext_header_size + sizeof(SceSelfAuthHeaderKey));

	res = ksceSblDmac5AesCbcDec(decrypt_point, decrypt_point, DecryptSize, pHeaderKey->key, 0x80, ref00d_private_header_iv, 1);
	if(res < 0){
		ksceDebugPrintf("%s:ksceSblDmac5AesCbcDec failed : 0x%X\n", __FUNCTION__, res);
		return res;
	}

	pHeaderInfo = decrypt_point;
	decrypt_point += sizeof(SceSelfAuthHeaderInfo);

	/*
	 * Does PS Vita only support RSA2048(type5)
	 */
	if(pHeaderInfo->sig_type != 5){
		ksceDebugPrintf("unknown sig type : 0x%X\n", pHeaderInfo->sig_type);
		return 0x800F0625;
	}

	pSegmentInfo = decrypt_point;
	decrypt_point += (sizeof(SceSelfAuthSegmentInfo) * pHeaderInfo->section_num);

	pKeyBase = decrypt_point;

	return 0;
}

int decrypt_module(const void *header, SceSize header_size, SceSblSmCommContext130 *ctx130){

	int res;
	uint64_t sysver = 0LL;
	SceSelfAuthInfo self_auth_info;
	cf_header *cf_hdr;
	ext_header *ext_hdr;
	SCE_appinfo *appinfo;
	PSVita_CONTROL_INFO *control_info;

	if((header_size > 0x1000) || (((SCE_header *)header)->header_len > 0x1000))
		return -1;

	memcpy(ref00d_private_header, header, header_size);
	memcpy(&self_auth_info, &ctx130->self_auth_info, sizeof(SceSelfAuthInfo));

	cf_hdr       = (cf_header           *)(ref00d_private_header);

	if((cf_hdr->m_magic != 0x454353) || (cf_hdr->m_version != 3) || ((cf_hdr->attributes.m_platform & 0x40) == 0) || ((cf_hdr->m_ext_header_size & 0xF) != 0))
		return 0x800f0624;

	ext_hdr      = (ext_header          *)(&ref00d_private_header[sizeof(cf_header)]);
	appinfo      = (SCE_appinfo         *)(&ref00d_private_header[ext_hdr->appinfo_offset]);
	control_info = (PSVita_CONTROL_INFO *)(&ref00d_private_header[ext_hdr->controlinfo_offset]);

	int next = 0;

	do {
		next = control_info->next & 1;
		switch(control_info->type){
		case 4:
			sysver = control_info->PSVita_elf_digest_info.min_required_fw;
			break;
		case 7:
			memcpy(&self_auth_info.padding2, control_info->PSVita_shared_secret_info.shared_secret_0, 0x10);
			break;
		}
		control_info = (PSVita_CONTROL_INFO *)((char *)control_info + control_info->size);
	} while(next == 1);

	if(sysver == 0LL)
		sysver = appinfo->version;
/*
	if(appinfo->self_type == APP){
		key_index = get_key(NPDRM, cf_hdr->m_category, sysver, (cf_hdr->attributes.m_sdk_type >= 2) ? 1 : 0, appinfo->self_type, 0);
		if(key_index < 0)
			return -1;

		res = remove_npdrm_personalize(cf_hdr, kprx_auth_key_list[key_index].key, &self_auth_info.klicensee);
		if(res < 0)
			return res;
	}
*/

	/*
	 * decrypt and get section
	 */
	res = decrypt_certified_personalize(g_key_info);
	if(res < 0){
		ksceDebugPrintf("decrypt_certified_personalize failed.\n");
		return res;
	}

	const SceSelfAuthMetaInfo *pMetaInfo = (const SceSelfAuthMetaInfo *)(((uintptr_t)pKeyBase) + (pHeaderInfo->seg_keys_area_size * 0x10));

	do {
		next = pMetaInfo->next & 1;
		switch(pMetaInfo->type){
		case 1:
			memcpy(&self_auth_info.capability, &pMetaInfo->PSVITA_caps_info.capability, sizeof(self_auth_info.capability));
			break;
		case 3:
			memcpy(&self_auth_info.attributes, &pMetaInfo->PSVITA_attr_info.attributes, sizeof(self_auth_info.attributes));
			break;
		}
		pMetaInfo = (SceSelfAuthMetaInfo *)(((uintptr_t)pMetaInfo) + pMetaInfo->size);
	} while(next == 1);

	self_auth_info.program_authority_id = appinfo->authid;

	memcpy(&ctx130->self_auth_info, &self_auth_info, sizeof(SceSelfAuthInfo));

	return 0;
}

int ref00d_wait_sema(void){
	int res;

	printf("ref00d_wait_sema start\n");

	res = ksceKernelWaitSema(semaid, 1, NULL);
	if(res > 0)
		res = 0;

	printf("ref00d_wait_sema end\n");

	return res;
}

int ref00d_auth_set_key(const void *key, const void *iv, SceSize keysize){

	memset(g_key_info, 0, sizeof(*g_key_info));

	if(keysize > 0x20)
		keysize = 0x20;

	if(key != NULL)
		memcpy(g_key_info->key, key, keysize);

	if(iv != NULL)
		memcpy(g_key_info->iv, iv, 0x10);

	return 0;
}

int ref00d_auth_open(int *ctx){
	int res;

	is_auth_success = 0;

	if(ctx == NULL){
		printf("ref00d_auth_open ctx == NULL\n");
		return -1;
	}

	res = ref00d_wait_sema();
	if(res == 0){
		*ctx = 1;
	}

	return res;
}

int ref00d_auth_close(int ctx){
	int res;

	is_auth_success = 0;

	if(ctx != 1){
		printf("ref00d_auth_close ctx != 1\n");
		return -1;
	}

	printf("ref00d_auth_close SignalSema start\n");

	res = ksceKernelSignalSema(semaid, 1);
	if(res > 0)
		res = 0;

	printf("ref00d_auth_close SignalSema end\n");

	return res;
}

int ref00d_auth_header(int ctx, const void *header, SceSize header_size, SceSblSmCommContext130 *ctx130){

	int res;

	if(ctx != 1){
		printf("ref00d_auth_header : 0x800F0624\n");
		return 0x800F0624;
	}

	res = decrypt_module(header, header_size, ctx130);

	is_auth_success = ((res >> 0x1F) ^ 1) & 1;

	printf("decrypt_module : 0x%X, is_auth_success %X\n", res, is_auth_success);
	return res;
}

int ref00d_load_block(int ctx, void *buffer, SceSize len){

	if((ctx != 1) || (is_auth_success == 0)){
		printf("ref00d_load_block : 0x800F0624\n");
		return 0x800F0624;
	}

	if(pSegmentInfo[currentKey].section_encryption == AES128CTR){
		printf("ref00d_load_block 0x%X, 0x%X\n", buffer, len);

		const void *key = (const void *)(((uintptr_t)pKeyBase) + (pSegmentInfo[currentKey].section_key_idx * 0x10));

		ksceSblDmac5AesCtrDec(buffer, buffer, len, key, 0x80, ref00d_private_iv, 1);
	}else{
		printf("ref00d_load_block not supported format\n");
	}

	return 0;
}

int ref00d_setup_segment(int ctx, int seg_idx){

	if((ctx != 1) || (is_auth_success == 0)){
		printf("ref00d_setup_segment : 0x800F0624\n");
		return 0x800F0624;
	}

	for(int i=0;i<pHeaderInfo->section_num;i++){
		if(pSegmentInfo[i].section_idx == seg_idx){

			printf("ref00d_setup_segment\n");
			printf("found key idx : 0x%X\n", i);

			currentKey = i;

			const void *iv = (pKeyBase + (pSegmentInfo[currentKey].section_iv_idx * 0x10));

			__swap_data(ref00d_private_iv, iv, sizeof(ref00d_private_iv)); // For Dmac AesCtr

			return pSegmentInfo[i].section_compression;
		}
	}

	printf("not found key idx\n");
	return -1;
}

int ref00d_get_internal_header(void *dst, SceSize *dstlen){

	if(is_auth_success != 1)
		return -1;

	if(((SCE_header *)ref00d_private_header)->header_len < *dstlen)
		*dstlen = ((SCE_header *)ref00d_private_header)->header_len;

	memcpy(dst, ref00d_private_header, *dstlen);

	return 0;
}

int ref00d_segment_num(int *num){

	if(is_auth_success == 0)
		return 0x800F0624;

	*num = pHeaderInfo->section_num;
	return 0;
}

int ref00d_segment_info(int seg_idx, SceSelfAuthSegmentInfo *data){

	if(is_auth_success == 0)
		return 0x800F0624;

	for(int i=0;i<pHeaderInfo->section_num;i++){
		if(pSegmentInfo[i].section_idx == seg_idx){
			memcpy(data, &pSegmentInfo[i], sizeof(SceSelfAuthSegmentInfo));
			return 0;
		}
	}

	return -1;
}

int ref00d_kprx_auth_state(void){

	if(is_auth_success == 0)
		return 0x800F0624;

	return 0;
}

int ref00d_auth_module(int ctx, const void *module, SceSize size){

	int res;
	cf_header *cf_hdr;
	ext_header *ext_hdr;

	cf_hdr       = (cf_header           *)(module);

	if((cf_hdr->m_magic != 0x454353) || (cf_hdr->m_version != 3) || ((cf_hdr->attributes.m_platform & 0x40) == 0) || ((cf_hdr->m_ext_header_size & 0xF) != 0))
		return 0x800f0624;

	ext_hdr      = (ext_header          *)(&ref00d_private_header[sizeof(cf_header)]);

	Elf32_Ehdr *pEhdr = (Elf32_Ehdr *)(module + ext_hdr->elf_offset);
	Elf32_Phdr *pPhdr = (Elf32_Phdr *)(module + ext_hdr->phdr_offset);
	segment_info *pSegInfo = (segment_info *)(module + ext_hdr->section_info_offset);

	for(int i=0;i<pEhdr->e_phnum;i++){

		res = ref00d_setup_segment(ctx, i);
		if(res < 0){
			ksceDebugPrintf("%s:ref00d_setup_segment failed 0x%X\n", __FUNCTION__, res);
			return res;
		}

		res = ref00d_load_block(ctx, (void *)(module + pSegInfo[i].offset), pPhdr[i].p_filesz);
		if(res < 0){
			ksceDebugPrintf("%s:ref00d_load_block failed 0x%X\n", __FUNCTION__, res);
			return res;
		}
	}

	return 0;
}
