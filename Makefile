#   -*- fundamental -*-
# 
#  $Id: Makefile,v 1.3 1999/01/07 15:01:37 tri Exp $
#  ----------------------------------------------------------------------
#  Makefile for irc encryption library
#  ----------------------------------------------------------------------
#  Created      : Sat Mar  1 21:02:50 1997 tri
#  Last modified: Thu Jan  7 14:00:55 1999 tri
#  ----------------------------------------------------------------------
#  Copyright © 1997, 1999
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

CFLAGS+=-g -L. -pedantic

LIBSRC=	irc_api.c \
	crc32.c \
	irc_crc.c \
	irc_crypt.c \
	irc_idea_v1.c \
	irc_idea_v2.c \
	irc_idea_v3.c \
	irc_b64.c \
	idea.c \
	misc.c
LIBOBJ=$(LIBSRC:.c=.o)

all: circ_shell test_exp

circ_shell: circ_shell.o libirccrypt.a
	$(CC) $(CFLAGS) -o circ_shell circ_shell.o -lirccrypt

test_exp: test_exp.o libirccrypt.a
	$(CC) $(CFLAGS) -o test_exp test_exp.o -lirccrypt

libirccrypt.a: $(LIBOBJ)
	rm -f libirccrypt.a
	$(AR) -rvu libirccrypt.a $(LIBOBJ)
	$(RANLIB) libirccrypt.a


clean:
	rm -f *.o *~

clobber:
	rm -f circ_shell test_exp libirccrypt.a *.o

# eof (Makefile)
