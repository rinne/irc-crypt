/*   -*- c -*-
 *  
 *  $Id: circ_shell.c,v 1.2 1997/03/01 18:47:47 tri Exp $
 *  ----------------------------------------------------------------------
 *  Crypto for IRC.
 *  ----------------------------------------------------------------------
 *  Created      : Fri Feb 28 18:28:18 1997 tri
 *  Last modified: Sat Mar  1 20:41:24 1997 tri
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
    nick = next_token(&rest, " \t");
    if (!rest) {
	response(2, "Syntax error", 0, NULL, NULL);
	return;
    }
    addr = next_token(&rest, " \t");
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
    int tdiff;
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
    response(0, NULL, tdiff, nick, data);
    free(nick);
    free(data);
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
	else
	    cmd_unknown(rest);
	free(line);
    }
    cmd_quit(NULL);
    exit(0);
}
