/*
 * Keyset manager
 * Copyright (C) 2021, Princess of Sleeping
 */

#ifndef _KEY_H_
#define _KEY_H_

int keyRegister(const char *file, const char *name, const void *key, SceSize size);
int keySaveRegisteredKeys(const char *path);

int keyGetRegisteredKey(const char *keyname, void *dst, SceSize size);

#endif /* _KEY_H_ */
