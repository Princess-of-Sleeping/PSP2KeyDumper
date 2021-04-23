/*
 * Easy FAT16 Library
 * Copyright (C) 2021, Princess of Sleeping
 */

#ifndef _FAT16_API_H_
#define _FAT16_API_H_

#include "fat16_internal.h"

#define FAT16_PART_RERMISSION_RD (1)
#define FAT16_PART_RERMISSION_RW (2)
#define FAT16_PART_RERMISSION_RDRW (FAT16_PART_RERMISSION_RD | FAT16_PART_RERMISSION_RW)

int fatAddPartCtx(const char *drive, int flags, const void *args, int args_size, FatReadSectorFunc fatReadSectorFunc, FatWriteSectorFunc fatWriteSectorFunc);

int fatIoOpen(const char *path, int flags, int mode);
int fatIoClose(int fd);

int fatIoRead(int fd, void *data, uint32_t size);
int fatIoWriteLimited(int fd, void *data, uint32_t size);

int fatIoLseek(int fd, int offset, int whence);

#endif	/* _FAT16_API_H_ */
