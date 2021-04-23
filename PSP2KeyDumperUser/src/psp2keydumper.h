/*
 * PSP2KeyDumper
 * Copyright (C) 2021, Princess of Sleeping
 */

/*
 * main <-> dumper bridge
 */

#ifndef _PSP2KEYDUMPER_H_
#define _PSP2KEYDUMPER_H_

#include <psp2/types.h>
#include "slb2.h"

int decrypt_enc(SceSlb2Context *pSlb2Ctx, const char *name, void *data, SceSize *length);

int extract_second_loader_360_key(SceSlb2Context *pSlb2Ctx);
int extract_secure_kernel_360_key(SceSlb2Context *pSlb2Ctx);

int extract_kprx_auth_360_key(SceSlb2Context *pSlb2Ctx);
int extract_update_service_360_key(void);
int extract_act_360_key(void);
int extract_qaf_360_key(void);
int extract_pm_360_key(void);
int extract_aimgr_360_key(void);
int extract_encdec_w_portability_360_key(void);

#endif /* _PSP2KEYDUMPER_H_ */
