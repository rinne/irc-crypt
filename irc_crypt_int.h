/*   -*- c -*-
 *  
 *  $Id: irc_crypt_int.h,v 1.1 1997/03/01 16:36:44 tri Exp $
 *  ----------------------------------------------------------------------
 *  Crypto for IRC.
 *  ----------------------------------------------------------------------
 *  Created      : Fri Feb 28 18:28:18 1997 tri
 *  Last modified: Sat Mar  1 18:29:25 1997 tri
 *  ----------------------------------------------------------------------
 *  Copyright � 1997
 *  Timo J. Rinne <tri@iki.fi>
 * 
 *  Address: Cirion oy, PO-BOX 250, 00121 Helsinki, Finland
 *  ----------------------------------------------------------------------
 *  Any express or implied warranties are disclaimed.  In no event
 *  shall the author be liable for any damages caused (directly or
 *  otherwise) by the use of this software.
 */
#ifndef __IRC_CRYPT_H__
#define __IRC_CRYPT_H__ 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* IRC */
int irc_add_known_key(char *key);
int irc_delete_known_key(char *key);
int irc_add_default_key(char *addr, char *key);
int irc_delete_default_key(char *addr);
char *irc_encrypt_message_to_address(char *addr, char *nick, char *message);
char *irc_encrypt_message_with_key(char *key, char *nick, char *message);
int irc_decrypt_message(char *msg, 
			char **message, char **nick, unsigned int *tdiff);
int irc_is_encrypted_message_p(char *msg);

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
char *strxdup(char *str);

#endif /* ! __IRC_CRYPT_H__ 1 */
