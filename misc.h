/*
 * Copyright (c) 1995 Danny Gasparovski.
 *
 * Please read the file COPYRIGHT for the
 * terms and conditions of the copyright.
 */

#ifndef _MISC_H_
#define _MISC_H_

/* TCP emulations */
#define EMU_CTL 0x1
#define EMU_FTP 0x2
#define EMU_KSH 0x3
#define EMU_IRC 0x4
#define EMU_REALAUDIO 0x5
#define EMU_RLOGIN 0x6
#define EMU_IDENT 0x7
#define EMU_RSH 0x8

#define EMU_NOCONNECT 0x10      /* Don't connect */

struct tos_t {
	u_int16_t lport;
	u_int16_t fport;
	u_int8_t tos;
	u_int8_t emu;
};

#ifndef HAVE_STRDUP
char *strdup _P((const char *));
#endif


void slirp_insque _P((void *, void *));
void slirp_remque _P((void *));

#endif
