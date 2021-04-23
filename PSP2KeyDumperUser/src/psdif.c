/*
 * Pseudo storage device interface
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2/paf.h>
#include "psdif.h"

typedef struct PsdifDevice {
	struct PsdifDevice *next;
	int device_id;
	void *pDevice;
	SceSize size;
} PsdifDevice;

PsdifDevice *pPsdifDeviceTree = NULL;

int psdifRegisterDevice(void *pDevice, SceSize size){

	PsdifDevice *pPsdifDevice;

	pPsdifDevice = sce_paf_private_malloc(sizeof(*pPsdifDevice));
	if(pPsdifDevice == NULL)
		return -1;

	pPsdifDevice->next      = pPsdifDeviceTree;
	pPsdifDevice->device_id = ((int)pPsdifDevice) ^ 0x15482;
	if((pPsdifDevice->device_id & 0x80000000) != 0){
		pPsdifDevice->device_id &= ~0x80000000;
		pPsdifDevice->device_id ^=  0x7F3F7F3F;
	}

	pPsdifDevice->pDevice   = pDevice;
	pPsdifDevice->size      = size;

	pPsdifDeviceTree = pPsdifDevice;

	return pPsdifDevice->device_id;
}

int psdifUnregisterDevice(int deviceId){

	PsdifDevice *pPsdifDevice, **ppPsdifDevice;

	ppPsdifDevice = &pPsdifDeviceTree;
	while(*ppPsdifDevice != NULL){
		if((*ppPsdifDevice)->device_id == deviceId){

			pPsdifDevice = *ppPsdifDevice;

			*ppPsdifDevice = (*ppPsdifDevice)->next;

			sce_paf_private_free(pPsdifDevice);

			return 0;
		}

		ppPsdifDevice = &(*ppPsdifDevice)->next;
	}

	return -1;
}

PsdifDevice *psdifGetDevice(int deviceId){

	PsdifDevice *pPsdifDevice;

	pPsdifDevice = pPsdifDeviceTree;
	while(pPsdifDevice != NULL){
		if(pPsdifDevice->device_id == deviceId){
			return pPsdifDevice;
		}

		pPsdifDevice = pPsdifDevice->next;
	}

	return NULL;
}

int psdifReadSector(int deviceId, SceUInt32 sector_pos, void *data, SceUInt32 sector_num){

	PsdifDevice *pPsdifDevice = psdifGetDevice(deviceId);
	if(pPsdifDevice == NULL)
		return -1;

	SceUInt32 deviceSizeSector = pPsdifDevice->size >> 9;

	if(sector_pos >= deviceSizeSector || sector_num > deviceSizeSector || (sector_pos + sector_num) > deviceSizeSector)
		return -2;

	sce_paf_private_memcpy(data, pPsdifDevice->pDevice + (sector_pos << 9), sector_num << 9);

	return 0;
}
