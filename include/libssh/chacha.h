/* $OpenBSD: chacha.h,v 1.4 2016/08/27 04:04:56 guenther Exp $ */

/*
  chacha-merged.c version 20080118
  D. J. Bernstein
  Public domain.
*/

#ifndef CHACHA_H
#define CHACHA_H

#include <sys/types.h>
#include <stdlib.h>

struct chacha_ctx {
    unsigned int input[16];
};

#define CHACHA_MINKEYLEN   16
#define CHACHA_NONCELEN        8
#define CHACHA_CTRLEN      8
#define CHACHA_STATELEN        (CHACHA_NONCELEN+CHACHA_CTRLEN)
#define CHACHA_BLOCKLEN        64

void chacha_keysetup(struct chacha_ctx *x, const unsigned char *k, unsigned int kbits);
/* __attribute__((__bounded__(__minbytes__, 2, CHACHA_MINKEYLEN))); */
void chacha_ivsetup(struct chacha_ctx *x, const unsigned char *iv, const unsigned char *ctr);
/* __attribute__((__bounded__(__minbytes__, 2, CHACHA_NONCELEN))) */
/* __attribute__((__bounded__(__minbytes__, 3, CHACHA_CTRLEN))); */
void chacha_encrypt_bytes(struct chacha_ctx *x, const unsigned char *m,
                          unsigned char *c, unsigned int bytes);
/* __attribute__((__bounded__(__buffer__, 2, 4))) */
/* __attribute__((__bounded__(__buffer__, 3, 4))); */

#endif /* CHACHA_H */
