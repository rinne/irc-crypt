/*   -*- c -*-
 *  
 *  $Id: misc.c,v 1.6 2004/07/27 16:10:17 tri Exp $
 *  ----------------------------------------------------------------------
 *  Crypto for IRC.
 *  ----------------------------------------------------------------------
 *  Created      : Fri Feb 28 18:28:18 1997 tri
 *  Last modified: Tue Jul 27 19:08:28 2004 tri
 *  ----------------------------------------------------------------------
 *  Copyright © 1997, 1999, 2004
 *  Timo J. Rinne <tri@iki.fi>
 * 
 *  See file COPYRIGHT for license details.
 *  ----------------------------------------------------------------------
 *  Any express or implied warranties are disclaimed.  In no event
 *  shall the author be liable for any damages caused (directly or
 *  otherwise) by the use of this software.
 */
#include "irc_crypt_int.h"

char *str_concat(char *s1, char *s2)
{
    char *r;

    r = xmalloc(strlen(s1) + strlen(s2) + 1);
    strcpy(r, s1);
    strcat(r, s2);
    return r;
}

void *xmalloc(int l)
{
    char *r;
    r = (char *)malloc(l);
    if (!r) {
	fprintf(stderr, "Out of memory!\n");
	exit(1);
    }
    return r;
}

void *xcalloc(int n, int l)
{
    char *r;
    r = (char *)calloc(n, l);
    if (!r) {
	fprintf(stderr, "Out of memory!\n");
	exit(1);
    }
    return r;
}

int strciequal(char *s1, char *s2)
{
    return (strcicmp(s1, s2) == 0);
}

int strcicmp(char *s1, char *s2)
{
    while ((*s1) && (*s2)) {
	if (toupper(*s1) < toupper(*s2))
	    return -1;
	if (toupper(*s1) > toupper(*s2))
	    return 1;
	s1++;
	s2++;
    }
    if (!((*s1) || (*s2)))
	return 0;
    if (!(s1))
	return -1;
    return 1;
}

char *strxdup(char *str)
{
    return str_concat("", str);
}

