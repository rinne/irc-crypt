#   -*- fundamental -*-
# 
#  $Id: Makefile,v 1.1 1997/03/01 20:03:49 tri Exp $
#  ----------------------------------------------------------------------
#  Makefile for irc encryption library
#  ----------------------------------------------------------------------
#  Created      : Sat Mar  1 21:02:50 1997 tri
#  Last modified: Sat Mar  1 22:03:35 1997 tri
#  ----------------------------------------------------------------------
#  Copyright © 1997
#  Timo J. Rinne <tri@iki.fi>
# 
#  Address: Cirion oy, PO-BOX 250, 00121 Helsinki, Finland
#  ----------------------------------------------------------------------
#  Any express or implied warranties are disclaimed.  In no event
#  shall the author be liable for any damages caused (directly or
#  otherwise) by the use of this software.
#  
AR=ar
RANLIB=ranlib

CFLAGS+=-g -L.

LIBSRC=irc_api.c crc32.c irc_crc.c irc_crypt.c irc_b64.c idea.c misc.c
LIBOBJ=$(LIBSRC:.c=.o)

all: circ_shell

circ_shell: circ_shell.o libirccrypt.a
	$(CC) $(CFLAGS) -o circ_shell circ_shell.o -lirccrypt

libirccrypt.a: $(LIBOBJ)
	rm -f libirccrypt.a
	$(AR) -rvu libirccrypt.a $(LIBOBJ)
	$(RANLIB) libirccrypt.a

# eof (Makefile)
