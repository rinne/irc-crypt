/*   -*- c -*-
 *  
 *  $Id: circ_shell.c,v 1.7 1999/01/06 13:13:28 tri Exp $
 *  ----------------------------------------------------------------------
 *  Crypto for IRC.
 *  ----------------------------------------------------------------------
 *  Created      : Fri Feb 28 18:28:18 1997 tri
 *  Last modified: Wed Jan  6 15:13:02 1999 tri
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "irc_crypt.h"

void response(int err, char *errstr, int attr, char *attrstr, char *data)
{
    printf("%d%s%d%s%s\n", 
	   err, 
	   (err ? (errstr ? errstr : "Unknown") : "OK"),
	   attr,
	   attrstr ? attrstr : "",
	   data ? data : "");
}

#define BUF_MAL_STEP 64
char *read_line(FILE *f)
{
    char *buf, *ptr, *nbuf;
    int  r=0, c, bsiz;
    
    if(NULL == (buf = malloc(BUF_MAL_STEP * sizeof(char))))
      return(NULL);
    
    bsiz = BUF_MAL_STEP;
    ptr = buf;
    while(EOF != (c = fgetc(f)) && c != '\n') {
        r++;
        *ptr++ = c;
        if(r + 3 >= bsiz) {
            if(NULL == (nbuf = malloc(bsiz + BUF_MAL_STEP * sizeof(char)))) {
                return(NULL);
            }
            strncpy(nbuf, buf, bsiz);
            free(buf);
            buf = nbuf;
            ptr = &buf[r];
            bsiz += BUF_MAL_STEP;
        }
    }
    if(!r && EOF ==c) {
        free(buf);
        return(NULL);
    }
    *ptr = 0;
    return(buf);
}

char *next_token(char **str, char *delim)
{
    char *r;

    r = strsep(str, delim);
    if (!(*str))
	return r;
    while (index(delim, **str))
	(*str)++;
    return r;
}


void cmd_quit(char *rest)
{
    response(0, NULL, 0, NULL, "QUIT");
    exit(0);
}

void cmd_addkey(char *rest)
{
    char *cmd, *chnl, *key;

    cmd = next_token(&rest, " \t");
    if (!rest) {
	response(2, "Syntax error", 0, NULL, NULL);
	return;
    }

    if (strciequal("default", cmd)) {
	chnl = next_token(&rest, " \t");
	if ((!rest) || ((*rest) != ':')) {
	    response(2, "Syntax error", 0, NULL, NULL);
	    return;
	}
	irc_add_default_key(chnl, &(rest[1]));
	response(0, NULL, 0, NULL, "ADDKEY");
    } else if (strciequal("decrypt", cmd)) {
	if ((!rest) || ((*rest) != ':')) {
	    response(2, "Syntax error", 0, NULL, NULL);
	    return;
	}
	irc_add_known_key(&(rest[1]));
	response(0, NULL, 0, NULL, "ADDKEY");
	return;
    } else {
	response(2, "Syntax error", 0, NULL, NULL);
	return;
    }
}

void cmd_deletekey(char *rest)
{
    char *cmd, *chnl, *key;
    int r;

    cmd = next_token(&rest, " \t");
    if (strciequal("default", cmd)) {
	if (!rest) {
	    response(2, "Syntax error", 0, NULL, NULL);
	    return;
	}
	chnl = next_token(&rest, " \t");
	r = irc_delete_default_key(chnl);
	response(0, NULL, (!r), ((!r) ? "No key for address" : NULL),
		 "DELETEKEY");
    } else if (strciequal("decrypt", cmd)) {
	if ((!rest) || ((*rest) != ':')) {
	    response(2, "Syntax error", 0, NULL, NULL);
	    return;
	}
	r = irc_delete_known_key(&(rest[1]));
	response(0, NULL, (!r), ((!r) ? "Not a known key" : NULL),
		 "DELETEKEY");
    } else if (strciequal("all", cmd)) {
	irc_delete_all_keys();
	response(0, NULL, 0, NULL, "DELETEKEY");
	return;
    } else {
	response(2, "Syntax error", 0, NULL, NULL);
	return;
    }
}

void cmd_encrypt(char *rest)
{
    char *nick, *addr;
    char *msg;
    addr = next_token(&rest, " \t");
    if (!rest) {
	response(2, "Syntax error", 0, NULL, NULL);
	return;
    }
    nick = next_token(&rest, " \t");
    if ((!rest) || ((*rest) != ':')) {
	response(2, "Syntax error", 0, NULL, NULL);
	return;
    }
    msg = irc_encrypt_message_to_address(addr, nick, &(rest[1]));
    if (!msg) {
	response(4, "Encryption error", 0, NULL, "No key");
	return;
    }
    response(0, NULL, 0, NULL, msg);
    free(msg);
    return;
}

void cmd_decrypt(char *rest)
{
    char *nick, *data;
    unsigned int tdiff;
    int r;

    if ((*rest) != ':') {
	response(2, "Syntax error", 0, NULL, NULL);
	return;
    }
    r = irc_decrypt_message(&(rest[1]), &data, &nick, &tdiff);
    if (!r) {
	response(3, "Decryption error", 0, NULL, data);
	return;
    }
    response(0, NULL, (int)tdiff, nick, data);
    free(nick);
    free(data);
    return;
}

void cmd_version(char *rest)
{
    int version, r;
    char buf[64];

    version = atoi(rest);

    r = irc_set_key_expand_version(version);

    if (r == 0) {
	sprintf(buf, "method = %d", irc_key_expand_version());
	response(3, "Syntax error", 0, buf, "VERSION");
    } else {
	sprintf(buf, "new method = %d, old method = %d", version, r);
	response(0, NULL, 0, buf, "VERSION");
    }
    return;
}

void cmd_help(char *rest)
{
    printf("  Commands: ADDKEY, DELETEKEY, ENCRYPT, DECRYPT, VERSION, HELP, QUIT\n\n");
    printf("    ADDKEY DECRYPT :key\n");
    printf("    Add key (string after colon) to the known key pool.\n\n");
    printf("    ADDKEY DEFAULT address :key\n");
    printf("    Add key (string after colon) as a default key for channel.\n\n");
    printf("    DELETEKEY ALL\n");
    printf("    Delete all (default and known) keys from keypools.\n\n");
    printf("    DELETEKEY DECRYPT :key\n");
    printf("    Delete key from known key pool.\n\n");
    printf("    DELETEKEY DEFAULT address\n");
    printf("    Delete default key associated woth address.\n\n");
    printf("    ENCRYPT address nick :message\n");
    printf("    Encrypt message to address with a default key associated with address.\n");
    printf("    Embed nick into the message.\n\n");
    printf("    DECRYPT :message\n");
    printf("    Decrypt message if possible.\n\n");
    printf("    VERSION #\n");
    printf("    Set default key expand version to # (1 or 2)\n\n");
    printf("    HELP\n");
    printf("    Get this help\n\n");
    printf("    QUIT\n");
    printf("    Quit this program\n\n");
    printf("  Responses:\n\n");
    printf("    All responses contain error code, error message, response attribute,\n");
    printf("    response attribute string, and response string.  Fields are separated\n");
    printf("    with ^A (ascii = 1).   Success response is usually 0^AOK^A0^A^A, but\n");
    printf("    empty fields can contain additional information.\n\n");
    printf("    The only complicated success response is response to decrypt command.\n");
    printf("    Response is 0^AOK^Atimestamp-error^Anick^Amessage-data.  Timestamp\n");
    printf("    error is difference between current time and timestamp embedded in \n");
    printf("    the message.  Nick is the embedded nickname.  Message-data is the\n");
    printf("    decrypted message.\n\n");
    response(0, NULL, 0, NULL, "HELP");
    return;
}

void cmd_unknown(char *rest)
{
    response(1, "Unknown command.", 0, NULL, "Ignored");
    return;
}

main()
{
    char *line;
    char *cmd, *rest, *hlp;

    while (line = read_line(stdin)) {
	hlp = line;
	cmd = next_token(&hlp, " \t");
	rest = hlp;
	if (strciequal("quit", cmd))
	    cmd_quit(rest);
	else if (strciequal("addkey", cmd))
	    cmd_addkey(rest);
	else if (strciequal("deletekey", cmd))
	    cmd_deletekey(rest);
	else if (strciequal("encrypt", cmd))
	    cmd_encrypt(rest);
	else if (strciequal("decrypt", cmd))
	    cmd_decrypt(rest);
	else if (strciequal("version", cmd))
	    cmd_version(rest);
	else if (strciequal("help", cmd))
	    cmd_help(rest);
	else
	    cmd_unknown(rest);
	free(line);
    }
    cmd_quit(NULL);
    exit(0);
}
