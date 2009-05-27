/*
 * Copyright (c) 1995 Danny Gasparovski.
 *
 * Please read the file COPYRIGHT for the
 * terms and conditions of the copyright.
 */

#define WANT_SYS_IOCTL_H
#include "slirp_common.h"


struct quehead {
	struct quehead *qh_link;
	struct quehead *qh_rlink;
};

inline void
slirp_insque(a, b)
	void *a, *b;
{
	register struct quehead *element = (struct quehead *) a;
	register struct quehead *head = (struct quehead *) b;
	element->qh_link = head->qh_link;
	head->qh_link = (struct quehead *)element;
	element->qh_rlink = (struct quehead *)head;
	((struct quehead *)(element->qh_link))->qh_rlink
	= (struct quehead *)element;
}

inline void
slirp_remque(a)
     void *a;
{
  register struct quehead *element = (struct quehead *) a;
  ((struct quehead *)(element->qh_link))->qh_rlink = element->qh_rlink;
  ((struct quehead *)(element->qh_rlink))->qh_link = element->qh_link;
  element->qh_rlink = NULL;
  /*  element->qh_link = NULL;  TCP FIN1 crashes if you do this.  Why ? */
}

/* #endif */


#ifndef HAVE_STRERROR

/*
 * For systems with no strerror
 */

extern int sys_nerr;
extern char *sys_errlist[];

char *
strerror(error)
	int error;
{
	if (error < sys_nerr)
	   return sys_errlist[error];
	else
	   return "Unknown error.";
}

#endif



#ifndef HAVE_STRDUP
char *
strdup(str)
	const char *str;
{
	char *bptr;

	bptr = (char *)malloc(strlen(str)+1);
	strcpy(bptr, str);

	return bptr;
}
#endif

#if 0 // TODO: tmp term_vprintf is defined in qemu.
extern void term_vprintf(const char *fmt, va_list ap);

void lprint(const char *format, ...)
{
    va_list args;

    va_start(args, format);
    term_vprintf(format, args);
    va_end(args);
}

#endif
