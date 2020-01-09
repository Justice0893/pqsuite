#ifndef _PACK_H
#define _PACK_H

#include "params.h"

void pack(unsigned char *out, const size_t outlen, const uint16_t *in, const size_t inlen, const unsigned char lsb);

void unpack(uint16_t *out, const size_t outlen, const unsigned char *in, const size_t inlen, const unsigned char lsb);

void clear_words(void* mem, unsigned int nwords);

void key_encode(uint16_t *out, const uint16_t *in);

void key_decode(uint16_t *out, const uint16_t *in);
#endif
