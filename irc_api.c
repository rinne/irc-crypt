/*   -*- c -*-
 *  
 *  $Id: irc_api.c,v 1.7 2004/07/27 16:10:17 tri Exp $
 *  ----------------------------------------------------------------------
 *  Crypto for IRC.
 *  ----------------------------------------------------------------------
 *  Created      : Fri Feb 28 18:28:18 1997 tri
 *  Last modified: Tue Jul 27 19:09:17 2004 tri
 *  ----------------------------------------------------------------------
 *  Copyright © 1997, 1999, 2004
 *  Timo J. Rinne <tri@iki.fi>
 * 
 *  See file COPYRIGHT for license details.
 *  ----------------------------------------------------------------------
 *  Any express or implied warranties are disclaimed.  In no event
 *  shall the author be liable for any damages caused (directly or
 *  otherwise) by the use of this software.
 */
#include "irc_crypt_int.h"

#define KEY_ALLOC_STEP 4

typedef struct {
    char *fingerprint;
    char *key;
} irc_key, *irc_key_t;

typedef struct {
    char *addr;
    char *key;
} irc_default_key, *irc_default_key_t;

static irc_key_t known_keys = NULL;
static int num_known_keys = 0;
static int spc_known_keys = 0;

static irc_default_key_t default_keys = NULL;
static int num_default_keys = 0;
static int spc_default_keys = 0;

static int irc_default_key_expand_version = 3;

static char *irc_get_known_key(char *fingerprint);
static char *irc_get_default_key(char *addr);
static int irc_add_known_key_internal(char *key, int version);

static int irc_parse_encrypted_message(char *msg,
				       char **type,
				       int *ver_maj,
				       int *ver_min,
				       char **fingerprint,
				       char **data)
{
    char *p1, *p2, *p3, *p4, *p5;
    char *hlp1, *hlp2;
    int x, vmaj, vmin;

    hlp1 = strsep(&msg, "|");
    if ((!hlp1) || (!msg) || (*hlp1))
	return 0;
    p1 = strsep(&msg, "|");
    if ((!msg) || (!p1))
	return 0;
    p2 = strsep(&msg, "|");
    if ((!msg) || (!p2))
	return 0;
    p3 = strsep(&msg, "|");
    if ((!msg) || (!p3))
	return 0;
    p4 = strsep(&msg, "|");
    if ((!msg) || (!p4))
	return 0;
    p5 = msg;
    x = strlen(p5);
    if ((x == 0) || (p5[x - 1] != '|'))
	return 0;
    p5[x - 1] = 0;

    hlp1 = strsep(&p3, ".");
    if ((!hlp1) || (!p3))
	return 0;
    hlp2 = strsep(&p3, ".");
    if (!hlp2)
	return 0;
    vmaj = atoi(hlp1);
    vmin = atoi(hlp2);
    if (strcmp("*E*", p1))
	return 0;
    if (type)
	*type = strxdup(p2);
    if (ver_maj)
	*ver_maj = vmaj;
    if (ver_min)
	*ver_min = vmin;
    if (fingerprint)
	*fingerprint = strxdup(p4);
    if (data)
	*data = strxdup(p5);
    return 1;
}

static char *irc_get_default_key(char *addr)
{
    int i;

    if (!default_keys)
	return NULL;
    
    for (i = 0; i < num_default_keys; i++)
	if (!(strcicmp(default_keys[i].addr, addr))) {
	    return strxdup(default_keys[i].key);
	}
    return NULL;
}

static char *irc_get_known_key(char *fingerprint)
{
    int i;

    if (!known_keys)
	return NULL;
    
    for (i = 0; i < num_known_keys; i++)
	if (!(strcicmp(known_keys[i].fingerprint, fingerprint)))
	    return strxdup(known_keys[i].key);
    return NULL;
}

static int irc_add_known_key_internal(char *key, int version)
{
    int i;
    char *fp;

    if (!known_keys) {
	known_keys = xcalloc(sizeof (irc_key), KEY_ALLOC_STEP);
	num_known_keys = 0;
	spc_known_keys = KEY_ALLOC_STEP;
    }
    if (num_known_keys == spc_known_keys) {
	irc_key_t n_keys;

	n_keys = xcalloc(sizeof (irc_key), KEY_ALLOC_STEP + spc_known_keys);
	memcpy(n_keys, known_keys, num_known_keys * sizeof (irc_key));
	free(known_keys);
	known_keys = n_keys;
	spc_known_keys += KEY_ALLOC_STEP;
    }
    fp = irc_key_fingerprint(key, version);
    for (i = 0; i < num_known_keys; i++)
	if (!(strcmp(known_keys[i].fingerprint, fp))) {
	    free(fp);
	    return 1; /* Already there */
	}
    known_keys[num_known_keys].key = strxdup(key);
    known_keys[num_known_keys].fingerprint = fp;
    num_known_keys++;
    return 1;
}

int irc_set_key_expand_version(int n)
{
    int x;

    if ((n == 1) || (n == 2) || (n == 3)) {
	x = irc_default_key_expand_version;
	irc_default_key_expand_version = n;
	return x;
    }
    return 0;
}

int irc_key_expand_version()
{
    return irc_default_key_expand_version;
}

int irc_add_known_key(char *key)
{
    int r;

    r = 1;
    r &= irc_add_known_key_internal(key, 1);
    r &= irc_add_known_key_internal(key, 2);
    r &= irc_add_known_key_internal(key, 3);

    return r;
}

int irc_delete_all_known_keys()
{
    int i;

    for (i = 0; i < num_known_keys; i++) {
	free(known_keys[i].key);
	free(known_keys[i].fingerprint);
    }
    num_known_keys = 0;
    return 1;
}

int irc_delete_all_default_keys()
{
    int i;

    for (i = 0; i < num_default_keys; i++) {
	free(default_keys[i].key);
	free(default_keys[i].addr);
    }
    num_default_keys = 0;
    return 1;
}

int irc_delete_all_keys()
{
    irc_delete_all_default_keys();
    irc_delete_all_known_keys();
    return 1;
}

int irc_delete_known_key(char *key)
{
    int i;

    if (!known_keys)
	return 0;
    
    for (i = 0; i < num_known_keys; i++)
	if (!(strcmp(known_keys[i].key, key))) {
	    free(known_keys[i].key);
	    free(known_keys[i].fingerprint);
	    num_known_keys--;
	    if (i < num_known_keys)
		memcpy(&(known_keys[i]), 
		       &(known_keys[i + 1]), 
		       (num_known_keys - i) * sizeof (irc_key));
	    return 1;
	}

    return 0;
}

int irc_add_default_key(char *addr, char *key)
{
    int i;

    if (!default_keys) {
	default_keys = xcalloc(sizeof (irc_default_key), KEY_ALLOC_STEP);
	num_default_keys = 0;
	spc_default_keys = KEY_ALLOC_STEP;
    }
    irc_delete_default_key(addr);
    if (!key)
	return 1;
    if (num_default_keys == spc_default_keys) {
	irc_default_key_t n_keys;

	n_keys = xcalloc(sizeof (irc_default_key), 
			 KEY_ALLOC_STEP + spc_default_keys);
	memcpy(n_keys, default_keys, 
	       num_default_keys * sizeof (irc_default_key));
	free(default_keys);
	default_keys = n_keys;
	spc_default_keys += KEY_ALLOC_STEP;
    }
    default_keys[num_default_keys].key = strxdup(key);
    default_keys[num_default_keys].addr = strxdup(addr);
    num_default_keys++;
    irc_add_known_key(key);
    return 1;
}

int irc_delete_default_key(char *addr)
{
    int i;

    if (!default_keys)
	return 0;
    
    for (i = 0; i < num_default_keys; i++)
	if (!(strcicmp(default_keys[i].addr, addr))) {
	    free(default_keys[i].key);
	    free(default_keys[i].addr);
	    num_default_keys--;
	    if (i < num_default_keys)
		memcpy(&(default_keys[i]), 
		       &(default_keys[i + 1]), 
		       (num_default_keys - i) * sizeof (irc_default_key));
	    return 1;
	}

    return 0;
}

char *irc_encrypt_message_to_address(char *addr, char *nick, char *message)
{
    char *key;
    char *r;

    key = irc_get_default_key(addr);
    if (!key)
	return NULL;
    r = irc_encrypt_message_with_key(key, nick, message);
    free(key);
    return r;
}

char *irc_encrypt_message_with_key(char *key, char *nick, char *message)
{
    char buf[16];
    char *r, *hlp, *hlp2;
    int x;

    switch (irc_default_key_expand_version) {
    case 1:
	r = "|*E*|IDEA|1.0|";
	break;
    case 2:
	r = "|*E*|IDEA|2.0|";
	break;
    case 3:
	r = "|*E*|IDEA|3.0|";
	break;
    default:
	return NULL;
    }
    r = str_concat(r, irc_key_fingerprint(key, 
					  irc_default_key_expand_version));
    hlp = r;
    r = str_concat(r, "|");
    free(hlp);

    hlp2 = str_concat(nick, "");
    hlp = hlp2;
    sprintf(buf, "%08x", time(NULL));
    hlp2 = str_concat(hlp2, buf);
    free(hlp);
    hlp = hlp2;
    hlp2 = str_concat(hlp2, "");
    free(hlp);
    hlp = hlp2;
    hlp2 = str_concat(hlp2, message);
    free(hlp);
    hlp = hlp2;
    x = strlen(hlp2);
    hlp2 = irc_encrypt_buffer(key, hlp2, &x);
    free(hlp);
    hlp = r;
    r = str_concat(r, hlp2);
    free(hlp);
    free(hlp2);
    hlp = r;
    r = str_concat(r, "|");
    free(hlp);
    return r;
}

int irc_decrypt_message(char *msg, 
			char **message, char **nick, unsigned int *tdiff)
{
    char *data, *fingerprint, *type;
    int vmaj, vmin;
    char *hlp1, *hlp2, *nn, *ts, *tx;
    int x;
    unsigned int tv, ct;
    int version;

    hlp1 = strxdup(msg);
    if (!(irc_parse_encrypted_message(hlp1, &type, &vmaj, &vmin,
				      &fingerprint, &data))) {
	free(hlp1);
	if (message)
	    *message = strxdup("Invalid message format");
	return 0;
    }
    if (strcmp(type, "IDEA")) {
	if (message)
	    *message = strxdup("Unknown algorithm");
	goto i_d_m_fail;
    }
    if ((vmaj == 1) && (vmin == 0)) {
	version = 1;
    } else if ((vmaj == 2) && (vmin == 0)) {
	version = 2;
    } else if ((vmaj == 3) && (vmin == 0)) {
	version = 3;
    } else {
	if (message)
	    *message = strxdup("Unknown version");
	goto i_d_m_fail;
    }
    hlp1 = irc_get_known_key(fingerprint);
    if (!hlp1) {
	if (message)
	    *message = strxdup("Unknown key");
	goto i_d_m_fail;
    }
    x = strlen(data);
    hlp2 = irc_decrypt_buffer(hlp1, data, &x, version);
    if (!hlp2) {
	if (message)
	    *message = strxdup("Decryption failed");
	goto i_d_m_fail;
    }
    hlp1 = hlp2;
    nn = strsep(&hlp2, "");
    if ((!nn) || (!hlp2)) {
	if (message)
	    *message = strxdup("Invalid data contents");
	goto i_d_m_fail;
    }
    nn = strxdup(nn);
    ts = strsep(&hlp2, "");
    if ((!ts) || (!hlp2)) {
	free(nn);
	if (message)
	    *message = strxdup("Invalid data contents");
	goto i_d_m_fail;
    }
    ts = strxdup(ts);
    tx = strxdup(hlp2);
    free(hlp1);

    tv = (unsigned int)strtol(ts, NULL, 16);
    free(ts);
    ct = (unsigned int)time(NULL);
    if (ct >= tv)
	x = (int)(ct - tv);
    else
	x = 0 - ((int)(ct - tv));
    
    if (message)
	*message = tx;
    if (nick)
	*nick = nn;
    if (tdiff)
	*tdiff = x;
    return 1;

i_d_m_fail:
    free(data);
    free(fingerprint);
    free(type);
    return 0;
}

int irc_is_encrypted_message_p(char *msg)
{
    char *hlp;
    int r;
    
    hlp = strxdup(msg);
    r = irc_parse_encrypted_message(hlp, NULL, NULL, NULL, NULL, NULL);
    free(hlp);
    return r;
}
