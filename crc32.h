/*   -*- c -*-
 *  
 *  ----------------------------------------------------------------------
 *  Crypto for IRC.
 *  ----------------------------------------------------------------------
 *  Created      : Fri Feb 28 18:28:18 1997 tri
 *  Last modified: Sat Feb  4 20:38:41 2017 tri
 *  ----------------------------------------------------------------------
 */
#ifndef CRC32_H
#define CRC32_H

/* This computes a 32 bit CRC of the data in the buffer, and returns the
   CRC.  The polynomial used is 0xedb88320. */
unsigned int crc32(const unsigned char *s, unsigned int len);

#endif /* CRC32_H */
