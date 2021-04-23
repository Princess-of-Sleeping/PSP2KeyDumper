/*
 * Pseudo storage device interface
 * Copyright (C) 2021, Princess of Sleeping
 */

#ifndef _PSEUDO_SDIF_H_
#define _PSEUDO_SDIF_H_

#include <psp2/types.h>

int psdifRegisterDevice(void *pDevice, SceSize size);
int psdifUnregisterDevice(int deviceId);

int psdifReadSector(int deviceId, SceUInt32 sector_pos, void *data, SceUInt32 sector_num);

#endif /* _PSEUDO_SDIF_H_ */
