/*   -*- c -*-
 *  
 *  $Id: misc.c,v 1.1 1997/03/01 16:36:44 tri Exp $
 *  ----------------------------------------------------------------------
 *  Crypto for IRC.
 *  ----------------------------------------------------------------------
 *  Created      : Fri Feb 28 18:28:18 1997 tri
 *  Last modified: Sat Mar  1 18:33:54 1997 tri
 *  ----------------------------------------------------------------------
 *  Copyright © 1997
 *  Timo J. Rinne <tri@iki.fi>
 * 
 *  Address: Cirion oy, PO-BOX 250, 00121 Helsinki, Finland
 *  ----------------------------------------------------------------------
 *  Any express or implied warranties are disclaimed.  In no event
 *  shall the author be liable for any damages caused (directly or
 *  otherwise) by the use of this software.
 */
#include "irc_crypt.h"

char *str_concat(char *s1, char *s2)
{
    char *r;

    r = xmalloc(strlen(s1) + strlen(s2) + 1);
    strcpy(r, s1);
    strcat(r, s2);
    return r;
}

char *xmalloc(int l)
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

#define BUF_MAL_STEP 64

char *read_line(FILE *f)
{
    char *buf, *ptr, *nbuf;
    int  r=0, c, bsiz;
    
    if(NULL == (buf = malloc(BUF_MAL_STEP * sizeof(char))))
      return(NULL);
    
    bsiz = BUF_MAL_STEP;
    ptr = buf;
    while(EOF != (c = fgetc(f)) && c != '\n') {
        r++;
        *ptr++ = c;
        if(r + 3 >= bsiz) {
            if(NULL == (nbuf = malloc(bsiz + BUF_MAL_STEP * sizeof(char)))) {
                return(NULL);
            }
            strncpy(nbuf, buf, bsiz);
            free(buf);
            buf = nbuf;
            ptr = &buf[r];
            bsiz += BUF_MAL_STEP;
        }
    }
    if(!r && EOF ==c) {
        free(buf);
        return(NULL);
    }
    *ptr = 0;
    return(buf);
}
