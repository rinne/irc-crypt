/*   -*- c -*-
 *  
 *  ----------------------------------------------------------------------
 *  Crypto for IRC.
 *  ----------------------------------------------------------------------
 *  Created      : Thu Jan  7 12:25:15 1999 tri
 *  Last modified: Sat Feb  4 20:41:13 2017 tri
 *  ----------------------------------------------------------------------
 *  Copyright © 1997, 1999, 2004, 2017
 *  Timo J. Rinne <tri@iki.fi>
 *
 *  See file COPYRIGHT for license details.
 *  ----------------------------------------------------------------------
 *  Any express or implied warranties are disclaimed.  In no event
 *  shall the author be liable for any damages caused (directly or
 *  otherwise) by the use of this software.
 */

#include "irc_crypt_int.h"

char *irc_idea_key_fingerprint_v1(char *key_str)
{
    unsigned short *b;
    unsigned char buf[16];

    b = irc_idea_key_expand_v1(key_str, -1);
    buf[15] = b[0] & 255;
    buf[14] = (b[0] >> 8) & 255;
    buf[13] = b[1] & 255;
    buf[12] = (b[1] >> 8) & 255;
    buf[11] = b[2] & 255;
    buf[10] = (b[2] >> 8) & 255;
    buf[9] = b[3] & 255;
    buf[8] = (b[3] >> 8) & 255;
    buf[7] = b[4] & 255;
    buf[6] = (b[4] >> 8) & 255;
    buf[5] = b[5] & 255;
    buf[4] = (b[5] >> 8) & 255;
    buf[3] = b[6] & 255;
    buf[2] = (b[6] >> 8) & 255;
    buf[1] = b[7] & 255;
    buf[0] = (b[7] >> 8) & 255;
    free(b);

    return irc_crc_buffer((char *)buf, 16);
}

unsigned short *irc_idea_key_expand_v1(char *str, int key_str_len)
{
    static unsigned short *key;
    char *keystr;
    char *hlp, *hlp2;
    char tmp[16];
    int i;
    int x1, x2, x3, x4;
    unsigned int c1, c2, c3, c4;

    key = xcalloc(8, sizeof (unsigned short));

    if (!(*str))
	return key;
    if (key_str_len < 0)
	key_str_len = strlen(str);
    if (key_str_len == 0)
	return key;

    keystr = str_concat(str, "");
    if (strlen(str) < 64) {
	for (i = 0; i < 8; i++) {
	    hlp = keystr;
	    hlp2 = irc_crc_string(hlp);
	    keystr = str_concat(hlp, hlp2);
	    free(hlp2);
	    free(hlp);
	}
    }

    i = strlen(keystr); 
    sprintf(tmp, "%d", i);
    hlp = keystr;
    keystr = str_concat(hlp, tmp);
    free(hlp);
    
    i = strlen(keystr); 
    x1 = 0;
    x2 = i / 4;
    x3 = 2 * (i / 4);
    x4 = 3 * (i / 4);

    c1 = irc_crc_string_numeric(&(keystr[x1]));
    c2 = irc_crc_string_numeric(&(keystr[x2]));
    c3 = irc_crc_string_numeric(&(keystr[x3]));
    c4 = irc_crc_string_numeric(&(keystr[x4]));

    key[0] = (unsigned short)((c1 >> 16) & 0xffff);
    key[1] = (unsigned short)(c1 & 0xffff);
    key[2] = (unsigned short)((c2 >> 16) & 0xffff);
    key[3] = (unsigned short)(c2 & 0xffff);
    key[4] = (unsigned short)((c3 >> 16) & 0xffff);
    key[5] = (unsigned short)(c3 & 0xffff);
    key[6] = (unsigned short)((c4 >> 16) & 0xffff);
    key[7] = (unsigned short)(c4 & 0xffff);

    return key;
}

/* eof (irc_idea_v1.c) */
