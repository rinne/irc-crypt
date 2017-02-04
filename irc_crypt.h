/*   -*- c -*-
 *  
 *  ----------------------------------------------------------------------
 *  Crypto for IRC.
 *  ----------------------------------------------------------------------
 *  Created      : Fri Feb 28 18:28:18 1997 tri
 *  Last modified: Sat Feb  4 20:41:15 2017 tri
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

/*
 * Set default key expand version to n.
 * Valid versions are 1, 2 and 3.  Default is 3.
 */
int irc_set_key_expand_version(int n);

/*
 * Return current default key expand version.
 */
int irc_key_expand_version(void);

/*
 * Expand a crypto-key from null-terminated string.
 */
unsigned short *irc_build_key(char *str, int version);

/*
 * Expand a crypto-key-fingerprint from null-terminated string.
 */
char *irc_key_fingerprint(char *key, int version);

#endif /* ! __IRC_CRYPT_H__ 1 */
