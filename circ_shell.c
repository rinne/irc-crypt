/*   -*- c -*-
 *  
 *  $Id: circ_shell.c,v 1.1 1997/03/01 16:36:44 tri Exp $
 *  ----------------------------------------------------------------------
 *  Crypto for IRC.
 *  ----------------------------------------------------------------------
 *  Created      : Fri Feb 28 18:28:18 1997 tri
 *  Last modified: Sat Mar  1 18:31:32 1997 tri
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

main()
{

#if 0
    unsigned short *key;
    int x;
    char *hlp, *hlp1, *hlp2, *hlp3;

    printf("kukkuu = %s\n", irc_crc_string("kukkuu"));
    printf("foo    = %s\n", irc_crc_string("foo"));

    x = 12;
    printf(">>>%s<<<", b64_encode_buffer("kukkuureseti", &x));
    printf(">>>%d<<<\n", x);
    
    x = 60;
    printf(">>>%s<<<", b64_decode_buffer("UGl0a+Qgb24gbWF0a2EgamEga2l25ORyaSBvbiByYXNrYXMga2FudGFhLg==", &x));
    printf(">>>%d<<<\n", x);

    x = 3;
    printf(">>>%s<<<", irc_encrypt_buffer("foo", "foo", &x));
    printf(">>>%d<<<\n", x);

    x = 24;
    printf(">>>%s<<<", irc_decrypt_buffer("foo", "Nhj1IEzJwwhqtdUQer/K3A==", &x));
    printf(">>>%d<<<\n", x);

    x = 88;
    printf(">>>%s<<<", irc_decrypt_buffer("foo", "tiCaSIwpU/ySCvQNiKfGUcZ4Ccw74+ruRWgttFnWMh22aMzWcgJ6cY5MJKrWo2VgVE3QhaKm6MB1+fNIluENvA==", &x));
    printf(">>>%d<<<\n", x);


    printf("%s -> %s\n", "foo", irc_key_fingerprint("foo"));

    printf(">> %s\n", irc_encrypt_message_with_key("foo", "Rinne", "kukkuureset"));


    irc_add_default_key("#zap", "foo");
    irc_add_default_key("#kukkuu", "bar");
    printf(">> %s\n", irc_encrypt_message_to_address("#kukkUU", "Rinne", "kukkuureset"));
    printf(">> %s\n", irc_encrypt_message_to_address("#zap", "Rinne", "kukkuureset"));

    if (irc_decrypt_message(irc_encrypt_message_with_key("foo", "Rinne", "kukkuureset"), &hlp1, &hlp2, &x)) {
	printf("1=\"%s\", 2=\"%s\", x=\"%d\"\n", hlp1, hlp2, x);
    }
    exit(0);
#endif
}
