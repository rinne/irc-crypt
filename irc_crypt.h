/*   -*- c -*-
 *  
 *  $Id: irc_crypt.h,v 1.2 1997/03/02 10:30:43 tri Exp $
 *  ----------------------------------------------------------------------
 *  Crypto for IRC.
 *  ----------------------------------------------------------------------
 *  Created      : Fri Feb 28 18:28:18 1997 tri
 *  Last modified: Sun Mar  2 12:29:29 1997 tri
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
/*
 * Add key to the known key pool.  These keys can be used to decrypt
 * messages.
 */
int irc_add_known_key(char *key);
/*
 * Delete key from the known key pool.  This function is usually 
 * not needed.
 */
int irc_delete_known_key(char *key);
/*
 * Add delault key for recipent (channel or nick).  This key is 
 * afterwards used to encrypt messages to this recipent with
 * irc_encrypt_message_to_address.
 */
int irc_add_default_key(char *addr, char *key);
/*
 * Delete default key from a recipent (channel or nick).
 */
int irc_delete_default_key(char *addr);
/*
 * Delete all default and known keys.
 */
int irc_delete_all_keys(void);
/*
 * Delete all default keys.
 */
int irc_delete_all_default_keys(void);
/*
 * Delete all known keys.
 */
int irc_delete_all_known_keys(void);
/*
 * Encrypt message to address (with default key).  Sender's nick is embedded 
 * to the message so that is also passed to the encryption function.
 *
 * Returns encrypted message or NULL if encryption fails.
 *
 * The space for message is reserved with malloc and it should me free'ed
 * accordingly.
 */
char *irc_encrypt_message_to_address(char *addr, char *nick, char *message);
/*
 * Encrypt message with key.  Sender's nick is embedded 
 * to the message so that is also passed to the encryption function.
 *
 * Returns encrypted message or NULL if encryption fails.
 *
 * The space for message is reserved with malloc and it should me free'ed
 * accordingly.
 */
char *irc_encrypt_message_with_key(char *key, char *nick, char *message);
/*
 * Decrypt message and turn pointers message nick and tdiff to 
 * point to decrypted message data, embedded nickname, error in 
 * timestamp (in seconds) accordingly.
 * 
 * If return value is non-nil, the decryption was succesfull and 
 * all pointers are valid.  If return value is 0, decryption was 
 * failed and only pointer message is valid containing an error
 * message string.
 *
 * The space for message (and nick if succeeded) is reserved with
 * malloc and it should me free'ed accordingly.
 */
int irc_decrypt_message(char *msg, 
			char **message, char **nick, unsigned int *tdiff);
/*
 * Return non-nil if message is in valid crypto message format.
 */
int irc_is_encrypted_message_p(char *msg);

#endif /* ! __IRC_CRYPT_H__ 1 */
