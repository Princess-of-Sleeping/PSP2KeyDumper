/*
 * SCE Spkg auth code
 * Copyright (C) 2021, Princess of Sleeping
 */

#ifndef _SPKG_AUTH_H_
#define _SPKG_AUTH_H_

int start_sm_update(void);
int stop_sm_update(void);

int auth_spkg(void *spkg_address, SceSize size);

#endif /* _SPKG_AUTH_H_ */
