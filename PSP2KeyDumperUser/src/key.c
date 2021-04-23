/*
 * Keyset manager
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2/kernel/clib.h>
#include <psp2/io/fcntl.h>
#include <psp2/paf.h>
#include "log.h"

typedef struct Keyring {
	struct Keyring *next;
	char   *key_file;
	char   *key_name;
	void   *key_data;
	SceSize key_size;
} Keyring;

Keyring *pKeyringTree = NULL;

int keyRegister(const char *file, const char *name, const void *key, SceSize size){

	if(name == NULL || key == NULL || (size - 1) >= 0x200)
		return -1;

	SceSize filelen = sce_paf_private_strlen(file);
	if(filelen == 0)
		return -1;

	SceSize namelen = sce_paf_private_strlen(name);
	if(namelen == 0)
		return -1;

	Keyring *pKeyring;

	pKeyring = sce_paf_private_malloc(sizeof(*pKeyring));
	if(pKeyring == NULL)
		return -1;


	char *key_file;

	key_file = sce_paf_private_malloc(filelen + 1);
	if(key_file == NULL)
		return -1;

	key_file[filelen] = 0;
	sce_paf_private_memcpy(key_file, file, filelen);



	char *key_name;

	key_name = sce_paf_private_malloc(namelen + 1);
	if(key_name == NULL)
		return -1;

	key_name[namelen] = 0;
	sce_paf_private_memcpy(key_name, name, namelen);


	char *key_data;

	key_data = sce_paf_private_malloc(size);
	if(key_data == NULL)
		return -1;

	sce_paf_private_memcpy(key_data, key, size);

	sce_paf_private_memset(pKeyring, 0, sizeof(*pKeyring));

	pKeyring->next = pKeyringTree;
	pKeyring->key_file = key_file;
	pKeyring->key_name = key_name;
	pKeyring->key_data = key_data;
	pKeyring->key_size = size;

	pKeyringTree = pKeyring;

	return 0;
}

int keySave(const char *path, const char *name, const void *key, SceSize size){

	LogOpen(path);

	LogWrite("const char %s[0x%X] = {\n", name, size);

	while(size > 0x10){

		LogWrite("\t");
		LogWrite("0x%02X, 0x%02X, 0x%02X, 0x%02X, ", ((char *)key)[0x0], ((char *)key)[0x1], ((char *)key)[0x2], ((char *)key)[0x3]);
		LogWrite("0x%02X, 0x%02X, 0x%02X, 0x%02X, ", ((char *)key)[0x4], ((char *)key)[0x5], ((char *)key)[0x6], ((char *)key)[0x7]);
		LogWrite("0x%02X, 0x%02X, 0x%02X, 0x%02X, ", ((char *)key)[0x8], ((char *)key)[0x9], ((char *)key)[0xA], ((char *)key)[0xB]);
		LogWrite("0x%02X, 0x%02X, 0x%02X, 0x%02X,\n", ((char *)key)[0xC], ((char *)key)[0xD], ((char *)key)[0xE], ((char *)key)[0xF]);

		key  += 0x10;
		size -= 0x10;
	}

	if(size != 0){

		LogWrite("\t");

		while(size > 1){
			LogWrite("0x%02X, ", ((char *)key)[0x0]);

			key  += 1;
			size -= 1;
		}

		while(size >= 1){
			LogWrite("0x%02X", ((char *)key)[0x0]);

			key  += 1;
			size -= 1;
		}

		LogWrite("\n}\n\n");
	}

	LogClose();

	return 0;
}

int keySaveRegisteredKeys(const char *path){

	char dst_path[0x400];
	Keyring *pKeyring = pKeyringTree;

	sce_paf_private_snprintf(dst_path, sizeof(dst_path), "%s/.key_flag", path);

	SceUID fd = sceIoOpen(dst_path, SCE_O_RDONLY, 0);
	if(fd >= 0){
		sceIoClose(fd);
		sceClibPrintf("Key already saved. If you want save key again, Remove to %s and key .c files\n", dst_path);
		return 0;
	}

	fd = sceIoOpen(dst_path, SCE_O_WRONLY | SCE_O_CREAT, 0666);
	sceIoClose(fd);

	while(pKeyring != NULL){

		sce_paf_private_snprintf(dst_path, sizeof(dst_path), "%s%s.c", path, pKeyring->key_file);

		keySave(dst_path, pKeyring->key_name, pKeyring->key_data, pKeyring->key_size);

		pKeyring = pKeyring->next;
	}

	return 0;
}

int keyGetRegisteredKey(const char *keyname, void *dst, SceSize size){

	Keyring *pKeyring = pKeyringTree;

	while(pKeyring != NULL){

		if(sce_paf_private_strcmp(keyname, pKeyring->key_name) == 0){

			if(size > pKeyring->key_size)
				size = pKeyring->key_size;

			sce_paf_private_memcpy(dst, pKeyring->key_data, size);

			return size;
		}

		pKeyring = pKeyring->next;
	}

	return -1;
}
