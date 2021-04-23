/*
 * Log manager
 * Copyright (C) 2021, Princess of Sleeping
 */

#ifndef _LOG_H_
#define _LOG_H_

int LogIsOpened(void);
int LogOpen(const char *path);
int LogWrite(const char *fmt, ...);
int LogClose(void);

#endif /* _LOG_H_ */
