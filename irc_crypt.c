/*   -*- c -*-
 *  
 *  $Id: irc_crypt.c,v 1.7 1999/01/06 13:10:23 tri Exp $
 *  ----------------------------------------------------------------------
 *  Crypto for IRC.
 *  ----------------------------------------------------------------------
 *  Created      : Fri Feb 28 18:28:18 1997 tri
 *  Last modified: Wed Jan  6 15:08:55 1999 tri
 *  ----------------------------------------------------------------------
 *  Copyright © 1997, 1999
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

/* Prototypes for v3 key expand stuff... */
static unsigned short *cleartext_string_to_block_list(char *str, 
						      int len, 
						      int *block_len);
static void interlace_block_list(unsigned short *buf, int buf_len);
static void xor_idea_blocks(unsigned short *dst, unsigned short *src);
static unsigned short *idea_v3_key_expand(char *str, int len);
/* End of v3 prototypes */

static unsigned short *build_idea_key_1(char *str)
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

static unsigned short *build_idea_key_2(char *str)
{
    static unsigned short key[8];

    key[0] = key[2] = key[3] = key[4] = key[5] = key[6] = key[7] = 0;

    if (!(*str))
	return key;

    return key; /* XXX */
}

static unsigned short *build_idea_key_3(char *str)
{
    static unsigned short key[8];
    unsigned short *dyn_key;

    dyn_key = idea_v3_key_expand(str, strlen(str));
    key[0] = dyn_key[0]; key[1] = dyn_key[1]; key[2] = dyn_key[2];
    key[3] = dyn_key[3]; key[4] = dyn_key[4]; key[5] = dyn_key[5];
    key[6] = dyn_key[6]; key[7] = dyn_key[7];
    free(dyn_key);
    return key;
}


static unsigned short *build_idea_key(char *str, int version)
{
    switch (version) {
    case 1:
	return build_idea_key_1(str);
    case 2:
	return build_idea_key_2(str);
    case 3:
	return build_idea_key_3(str);
    default:
	return NULL;
    }
}

static char *irc_key_fingerprint_1(char *key)
{
    unsigned short *b;
    unsigned char buf[16];

    b = build_idea_key(key, 1);

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

static char *irc_key_fingerprint_2(char *key)
{
    unsigned short *b;
    unsigned char buf[16];

    b = build_idea_key(key, 2);

    return strxdup("000000000000"); /* XXX */
}

static char *irc_key_fingerprint_3(char *key)
{
    unsigned short *b;
    unsigned char buf[17];

    b = idea_v3_key_expand(key, strlen(key));
    if (b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 && 
	b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0) {
	return strxdup("0000000000000000"); /* XXX */
    }
    buf[15] = b[0] & 0xff;
    buf[14] = (b[0] >> 8) & 0xff;
    buf[13] = b[1] & 0xff;
    buf[12] = (b[1] >> 8) & 0xff;
    buf[11] = b[2] & 0xff;
    buf[10] = (b[2] >> 8) & 0xff;
    buf[9] = b[3] & 0xff;
    buf[8] = (b[3] >> 8) & 0xff;
    buf[7] = b[4] & 0xff;
    buf[6] = (b[4] >> 8) & 0xff;
    buf[5] = b[5] & 0xff;
    buf[4] = (b[5] >> 8) & 0xff;
    buf[3] = b[6] & 0xff;
    buf[2] = (b[6] >> 8) & 0xff;
    buf[1] = b[7] & 0xff;
    buf[0] = (b[7] >> 8) & 0xff;
    free(b);
    b = idea_v3_key_expand((char *)buf, 16);
    buf[0] = 'a' + (b[0] % 26);
    buf[1] = 'a' + (b[1] % 26);
    buf[2] = 'a' + (b[2] % 26);
    buf[3] = 'a' + (b[3] % 26);
    buf[4] = 'a' + (b[4] % 26);
    buf[5] = 'a' + (b[5] % 26);
    buf[6] = 'a' + (b[6] % 26);
    buf[7] = 'a' + (b[7] % 26);
    buf[8] = 'a' + ((b[0] >> 8) % 26);
    buf[9] = 'a' + ((b[1] >> 8) % 26);
    buf[10] = 'a' + ((b[2] >> 8) % 26);
    buf[11] = 'a' + ((b[3] >> 8) % 26);
    buf[12] = 'a' + ((b[4] >> 8) % 26);
    buf[13] = 'a' + ((b[5] >> 8) % 26);
    buf[14] = 'a' + ((b[6] >> 8) % 26);
    buf[15] = 'a' + ((b[7] >> 8) % 26);
    buf[16] = 0;
    free(b);
    b = build_idea_key(key, 2);
    return strxdup((char *)buf); /* XXX */
}

char *irc_key_fingerprint(char *key, int version)
{
    switch (version) {
    case 1:
	return irc_key_fingerprint_1(key);
    case 2:
	return irc_key_fingerprint_2(key);
    case 3:
	return irc_key_fingerprint_3(key);
    default:
	return NULL;
    }
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

    ExpandUserKey(build_idea_key(key, irc_key_expand_version()), wk);
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
    hlp = b64_encode_buffer((char *)buf, &len);
    *buflen = len;
    free(buf);
    return hlp;
}

char *irc_decrypt_buffer(char *key, char *str, int *buflen, int version)
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
    ExpandUserKey(build_idea_key(key, version), wk);
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
/*fprintf(stderr, ">>>str=\"...\", len=%d, pad=%d\n", len, padlen);*/
    hlp = (unsigned char *)strxdup((char *)&(buf[padlen]));
    free(buf);
    buf = (unsigned char *)hlp;
    hlp = (unsigned char *)strxdup((char *)&(buf[8]));
    buf[8] = 0;
    (*buflen) -= padlen + 8;
    if (!(irc_check_crc_buffer((char *)hlp, *buflen, (char *)buf))) {
	free(hlp);
	free(buf);
	return NULL;
    }
    free(buf);
    return (char *)hlp;
}

/*
 * Key expand version 3 stuff.
 */
static unsigned short *cleartext_string_to_block_list(char *str, 
						      int len, 
						      int *block_len)
{
    int padlen, i;
    unsigned char *buf;
    unsigned short *ret_buf;
    char *hlp;

    if (len < 0)
	len = strlen(str);
    padlen = 8 - (len % 8);
    if (padlen == 0)
        padlen = 8;
    buf = xmalloc(len + 9);
    for (i = 0; i < padlen; i++)
        buf[i] = 0;
    memcpy(&(buf[i + 8]), str, len);
    hlp = irc_crc_buffer(str, len);
    memcpy(&(buf[i]), hlp, 8);
    free(hlp);
    buf[0] = ((unsigned char)(buf[0] & 31)) |
	     ((unsigned char)(((padlen - 1) & 7) << 5));
    len += 8 + padlen;
    ret_buf = xcalloc(len / 2, sizeof (unsigned short));
    for (i = 0; i < len / 2; i++) {
	ret_buf[i] = ((((unsigned short)(buf[i * 2])) << 8) |
		      (((unsigned short)(buf[(i * 2) + 1]))));
    }
    free(buf);
    *block_len = len / 2;
    return ret_buf;
}

static void interlace_block_list(unsigned short *buf, int buf_len)
{
    unsigned short *nbuf;
    int i, j, b, l;

    nbuf = xcalloc(buf_len, sizeof (unsigned short));
    b = buf_len / 4;
    for (i = 0; i < b; i++) {
	j = i * 4;
	nbuf[(b * 0) + i] = buf[(i * 4) + 0];
	nbuf[(b * 1) + i] = buf[(i * 4) + 1];
	nbuf[(b * 2) + i] = buf[(i * 4) + 2];
	nbuf[(b * 3) + i] = buf[(i * 4) + 3];
    }
    for (i = 0; i < buf_len; i++)
	buf[i] = nbuf[i];
    free(nbuf);
}

static void xor_idea_blocks(unsigned short *dst, unsigned short *src)
{
    dst[0] ^= src[0];
    dst[1] ^= src[1];
    dst[2] ^= src[2];
    dst[3] ^= src[3];
}

static unsigned short *idea_v3_key_expand(char *str, int len)
{
    unsigned short r1[4], r2[4], r3[4], r4[4], ek[52], bl[4];
    unsigned short *kk;
    unsigned short *blk;
    int blk_len, i;

    kk = xcalloc(8, sizeof (unsigned short));

    if (len == 0)
      return kk;

    kk[0] = 31415; kk[1] = 58979; kk[2] = 32384; kk[3] = 62643;
    kk[4] = 38327; kk[5] = 16939; kk[6] =  5820; kk[7] = 45923;
    r1[0] =  7816; r1[1] = 40628; r1[2] = 62089; r1[3] =  3482;
    r2[0] = 53421; r2[1] = 17067; r2[2] = 13282; r2[3] = 30664;
    r3[0] = 44609; r3[1] = 55058; r3[2] = 22317; r3[3] = 25359;
    r4[0] = 40812; r4[1] = 17450; r4[2] = 28410; r4[3] = 27019;

    blk = cleartext_string_to_block_list(str, len, &blk_len);
    interlace_block_list(blk, blk_len);
    ExpandUserKey(kk, ek);
    for (i = 0; i < blk_len; i += 4) {
	bl[0] = blk[i + 0];
	bl[1] = blk[i + 1];
	bl[2] = blk[i + 2];
	bl[3] = blk[i + 3];
	xor_idea_blocks(bl, r2);
	Idea(bl, bl, ek);
	xor_idea_blocks(r1, bl);
	if ((i + 4) < blk_len) {
	    bl[0] = blk[i + 4];
	    bl[1] = blk[i + 5];
	    bl[2] = blk[i + 6];
	    bl[3] = blk[i + 7];
	    xor_idea_blocks(bl, r1);
	    Idea(bl, bl, ek);
	    xor_idea_blocks(r2, bl);
	}
    }
    kk[0] = r1[0]; kk[1] = r2[0]; kk[2] = r1[1]; kk[3] = r2[1]; 
    kk[4] = r1[2]; kk[5] = r2[2]; kk[6] = r1[3]; kk[7] = r2[3]; 
    ExpandUserKey(kk, ek);
    interlace_block_list(blk, blk_len);
    for (i = 0; i < blk_len; i += 4) {
	bl[0] = blk[i + 0];
	bl[1] = blk[i + 1];
	bl[2] = blk[i + 2];
	bl[3] = blk[i + 3];
	xor_idea_blocks(bl, r4);
	Idea(bl, bl, ek);
	xor_idea_blocks(r3, bl);
	if ((i + 4) < blk_len) {
	    bl[0] = blk[i + 4];
	    bl[1] = blk[i + 5];
	    bl[2] = blk[i + 6];
	    bl[3] = blk[i + 7];
	    xor_idea_blocks(bl, r3);
	    Idea(bl, bl, ek);
	    xor_idea_blocks(r4, bl);
	}
    }
    kk[0] = r3[0]; kk[1] = r4[0]; kk[2] = r3[1]; kk[3] = r4[1]; 
    kk[4] = r3[2]; kk[5] = r4[2]; kk[6] = r3[3]; kk[7] = r4[3]; 
    return kk;
}
/*
 * End of key expand version 3 stuff.
 */
