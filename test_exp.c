/*   -*- c -*-
 *  
 *  $Id: test_exp.c,v 1.2 2004/07/27 16:10:17 tri Exp $
 *  ----------------------------------------------------------------------
 *  Crypto for IRC.
 *  ----------------------------------------------------------------------
 *  Created      : Thu Jan  7 13:04:36 1999 tri
 *  Last modified: Tue Jul 27 19:08:23 2004 tri
 *  ----------------------------------------------------------------------
 *  Copyright © 1999, 2004
 *  Timo J. Rinne <tri@iki.fi>
 *
 *  See file COPYRIGHT for license details.
 *  ----------------------------------------------------------------------
 *  Any express or implied warranties are disclaimed.  In no event
 *  shall the author be liable for any damages caused (directly or
 *  otherwise) by the use of this software.
 */
#include "irc_crypt.h"

main(int argc, char **argv)
{
    char *arg;
    char *f;
    unsigned short *b;
    int i;

    arg = (argc > 1) ? argv[1] : "";

    for (i = 1; i <= 3; i++) {
	f = irc_key_fingerprint(arg, i);
	b = irc_build_key(arg, i);
	printf("v = %d keystring = \"%s\", print = \"%s\"\n",
	       i, arg, f);
	printf("key = (%u %u %u %u %u %u %u %u)\n\n",
	       b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
	free(f);
	free(b);
    }
    exit(0);
}
