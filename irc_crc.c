/*   -*- c -*-
 *  
 *  $Id: irc_crc.c,v 1.2 1997/03/01 20:06:11 tri Exp $
 *  ----------------------------------------------------------------------
 *  Crypto for IRC.
 *  ----------------------------------------------------------------------
 *  Created      : Fri Feb 28 18:28:18 1997 tri
 *  Last modified: Sat Mar  1 18:31:44 1997 tri
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
#include "irc_crypt_int.h"
#include "crc32.h"

char *irc_crc_string(char *str)
{
    char *buf = xmalloc(9);

    sprintf(buf, "%08x", irc_crc_string_numeric(str));
    return buf;
}

unsigned int irc_crc_string_numeric(char *str)
{
    return crc32((unsigned char *)str, strlen(str));
}

char *irc_crc_buffer(char *buf, int len)
{
    char *hlp = xmalloc(9);

    sprintf(hlp, "%08x", irc_crc_buffer_numeric(buf, len));
    return hlp;
}

unsigned int irc_crc_buffer_numeric(char *buf, int len)
{
    return crc32((unsigned char *)buf, len);
}

int irc_check_crc_string(char *str, char *crc)
{
    int r;
    char *crc2;

    crc2 = irc_crc_string(str);
    r = (0 == strcmp(crc, crc2));
    free(crc2);
    return (r);
}

int irc_check_crc_string_numeric(char *str, unsigned int crc)
{
    unsigned int crc2 = irc_crc_string_numeric(str);

    return (crc == crc2);
}

int irc_check_crc_buffer(char *str, int len, char *crc)
{
    int r;
    char *crc2;

    crc2 = irc_crc_buffer(str, len);
    r = (0 == strcmp(crc, crc2));
    free(crc2);
    return (r);
}

int irc_check_crc_buffer_numeric(char *str, int len, unsigned int crc)
{
    unsigned int crc2 = irc_crc_buffer_numeric(str, len);

    return (crc == crc2);
}
