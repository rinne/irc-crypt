/*   -*- c -*-
 *  
 *  $Id: irc_crypt.c,v 1.6 1997/05/06 07:48:49 tri Exp $
 *  ----------------------------------------------------------------------
 *  Crypto for IRC.
 *  ----------------------------------------------------------------------
 *  Created      : Fri Feb 28 18:28:18 1997 tri
 *  Last modified: Tue May  6 10:43:43 1997 tri
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
#include "idea.h"

static unsigned short *build_idea_key(char *str)
{
    static unsigned short key[8];
    char *keystr;
    char *hlp, *hlp2;
    char tmp[16];
    int i;
    int x1, x2, x3, x4;
    unsigned int c1, c2, c3, c4;

    key[0] = key[2] = key[3] = key[4] = key[5] = key[6] = key[7] = 0;

    if (!(*str))
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

char *irc_key_fingerprint(char *key)
{
    unsigned short *b;
    unsigned char buf[16];

    b = build_idea_key(key);

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

    return irc_crc_buffer((char *)buf, 16);
}

char *irc_encrypt_buffer(char *key, char *str, int *buflen)
{
    unsigned short wk[52];
    unsigned short ctx[4];
    unsigned short cb[4];
    int i, padlen, len;
    unsigned char *buf;
    char *hlp;
    static int srandom_called = 0;

    if (!srandom_called) {
	srandom(time(NULL) ^ getpid());
	srandom_called = 1;
    }
    len = *buflen;
    padlen = 8 - (len % 8);
    if (padlen == 0)
	padlen = 8;
    buf = xmalloc(len + 9);
    for (i = 0; i < padlen; i++)
	buf[i] = random() & 255;
    memcpy(&(buf[i + 8]), str, len);
    hlp = irc_crc_buffer(str, len);
    memcpy(&(buf[i]), hlp, 8);
    free(hlp);
    buf[0] = ((unsigned char)(buf[0] & 31)) |
	     ((unsigned char)(((padlen - 1) & 7) << 5));
    len += 8 + padlen;

/*fprintf(stderr, ">>>str=\"%s\", len=%d, pad=%d\n", str, len, padlen);*/

    ExpandUserKey(build_idea_key(key), wk);
    ctx[0] = ctx[1] = ctx[2] = ctx[3] = 0;
    for (i = 0; i < (len / 8); i++) {
	cb[0] = (((unsigned short)(buf[(i * 8) + 0]) << 8) | buf[(i * 8) + 1])
	    ^ ctx[0];
	cb[1] = (((unsigned short)(buf[(i * 8) + 2]) << 8) | buf[(i * 8) + 3])
	    ^ ctx[1];
	cb[2] = (((unsigned short)(buf[(i * 8) + 4]) << 8) | buf[(i * 8) + 5])
	    ^ ctx[2];
	cb[3] = (((unsigned short)(buf[(i * 8) + 6]) << 8) | buf[(i * 8) + 7])
	    ^ ctx[3];
	Idea(cb, ctx, wk);
	buf[(i * 8) + 0] = (ctx[0] >> 8) & 0xff;
	buf[(i * 8) + 1] = ctx[0] & 0xff;
	buf[(i * 8) + 2] = (ctx[1] >> 8) & 0xff;
	buf[(i * 8) + 3] = ctx[1] & 0xff;
	buf[(i * 8) + 4] = (ctx[2] >> 8) & 0xff;
	buf[(i * 8) + 5] = ctx[2] & 0xff;
	buf[(i * 8) + 6] = (ctx[3] >> 8) & 0xff;
	buf[(i * 8) + 7] = ctx[3] & 0xff;
    }
    hlp = b64_encode_buffer(buf, &len);
    *buflen = len;
    free(buf);
    return hlp;
}

char *irc_decrypt_buffer(char *key, char *str, int *buflen)
{
    unsigned short wk[52];
    unsigned short ctx[4];
    unsigned short cb[4];
    unsigned short tb[4];
    int i, padlen;
    int len;
    unsigned char *buf, *hlp;

    buf = (unsigned char *)b64_decode_buffer(str, buflen);
    if (!buf)
	return NULL;
    len = *buflen;
    if ((len % 8) || (len < 16)) {
	free(buf);
	return NULL;
    }
    ExpandUserKey(build_idea_key(key), wk);
    InvertIdeaKey(wk, wk);
    ctx[0] = ctx[1] = ctx[2] = ctx[3] = 0;
    for (i = 0; i < (len / 8); i++) {
	tb[0] = cb[0] = 
	    (((unsigned short)(buf[(i * 8) + 0]) << 8) | buf[(i * 8) + 1]);
	tb[1] = cb[1] =
	    (((unsigned short)(buf[(i * 8) + 2]) << 8) | buf[(i * 8) + 3]);
	tb[2] = cb[2] = 
	    (((unsigned short)(buf[(i * 8) + 4]) << 8) | buf[(i * 8) + 5]);
	tb[3] = cb[3] = 
	    (((unsigned short)(buf[(i * 8) + 6]) << 8) | buf[(i * 8) + 7]);
	Idea(cb, cb, wk);
	cb[0] = cb[0] ^ ctx[0];
	cb[1] = cb[1] ^ ctx[1];
	cb[2] = cb[2] ^ ctx[2];
	cb[3] = cb[3] ^ ctx[3];
	ctx[0] = tb[0];
	ctx[1] = tb[1];
	ctx[2] = tb[2];
	ctx[3] = tb[3];
	buf[(i * 8) + 0] = (cb[0] >> 8) & 0xff;
	buf[(i * 8) + 1] = cb[0] & 0xff;
	buf[(i * 8) + 2] = (cb[1] >> 8) & 0xff;
	buf[(i * 8) + 3] = cb[1] & 0xff;
	buf[(i * 8) + 4] = (cb[2] >> 8) & 0xff;
	buf[(i * 8) + 5] = cb[2] & 0xff;
	buf[(i * 8) + 6] = (cb[3] >> 8) & 0xff;
	buf[(i * 8) + 7] = cb[3] & 0xff;
    }
    buf[i * 8] = 0;
    padlen = (buf[0] >> 5) + 1;
fprintf(stderr, ">>>str=\"...\", len=%d, pad=%d\n", len, padlen);
    hlp = strxdup(&(buf[padlen]));
    free(buf);
    buf = hlp;
    hlp = strxdup(&(buf[8]));
    buf[8] = 0;
    (*buflen) -= padlen + 8;
    if (!(irc_check_crc_buffer(hlp, *buflen, buf))) {
	free(hlp);
	free(buf);
	return NULL;
    }
    free(buf);
    return hlp;
}
