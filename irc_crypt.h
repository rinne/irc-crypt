/*   -*- c -*-
 *  
 *  $Id: irc_crypt.h,v 1.1 1997/03/01 20:06:42 tri Exp $
 *  ----------------------------------------------------------------------
 *  Crypto for IRC.
 *  ----------------------------------------------------------------------
 *  Created      : Fri Feb 28 18:28:18 1997 tri
 *  Last modified: Sat Mar  1 21:51:49 1997 tri
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
#ifndef __IRC_CRYPT_H__
#define __IRC_CRYPT_H__ 1

/* API */
int irc_add_known_key(char *key);
int irc_delete_known_key(char *key);
int irc_add_default_key(char *addr, char *key);
int irc_delete_default_key(char *addr);
int irc_delete_all_keys(void);
char *irc_encrypt_message_to_address(char *addr, char *nick, char *message);
char *irc_encrypt_message_with_key(char *key, char *nick, char *message);
int irc_decrypt_message(char *msg, 
			char **message, char **nick, unsigned int *tdiff);
int irc_is_encrypted_message_p(char *msg);

#endif /* ! __IRC_CRYPT_H__ 1 */
