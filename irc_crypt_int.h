/*   -*- c -*-
 *  
 *  $Id: irc_crypt_int.h,v 1.3 1997/03/01 20:06:42 tri Exp $
 *  ----------------------------------------------------------------------
 *  Crypto for IRC.
 *  ----------------------------------------------------------------------
 *  Created      : Fri Feb 28 18:28:18 1997 tri
 *  Last modified: Sat Mar  1 21:54:28 1997 tri
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
#ifndef __IRC_CRYPT_INT_H__
#define __IRC_CRYPT_INT_H__ 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "irc_crypt.h"

/* CRC */
char *irc_crc_string(char *str);
char *irc_crc_buffer(char *buf, int len);
unsigned int irc_crc_string_numeric(char *str);
unsigned int irc_crc_buffer_numeric(char *buf, int len);
int irc_check_crc_string(char *str, char *crc);
int irc_check_crc_buffer(char *str, int len, char *crc);
int irc_check_crc_string_numeric(char *str, unsigned int crc);
int irc_check_crc_buffer_numeric(char *str, int len, unsigned int crc);

/* B64 */
char *b64_encode_buffer(char *buf, int *len);
char *b64_decode_buffer(char *buf, int *len);

/* CRYPT */
char *irc_encrypt_buffer(char *key, char *str, int *len);
char *irc_decrypt_buffer(char *key, char *str, int *len);
char *irc_key_fingerprint(char *key);

/* Misc */
char *str_concat(char *s1, char *s2);
char *xmalloc(int l);
void *xcalloc(int n, int l);
int strcicmp(char *s1, char *s2);
int strciequal(char *s1, char *s2);
char *strxdup(char *str);

#endif /* ! __IRC_CRYPT_INT_H__ 1 */
