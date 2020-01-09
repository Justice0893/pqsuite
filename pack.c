#include <string.h>
#include "pack.h"


#define min(x, y) (((x) < (y)) ? (x) : (y))

void pack(unsigned char *out, const size_t outlen, const uint16_t *in, const size_t inlen, const unsigned char lsb)
{ // Pack the input uint16 vector into a char output vector, copying lsb bits from each input element. 
  // If inlen * lsb / 8 > outlen, only outlen * 8 bits are copied.
	memset(out, 0, outlen);

	size_t i = 0;            // whole bytes already filled in
	size_t j = 0;            // whole uint16_t already copied
	uint16_t w = 0;          // the leftover, not yet copied
	unsigned char bits = 0;  // the number of lsb in w

	while (i < outlen && (j < inlen || ((j == inlen) && (bits > 0)))) {
		/*
		in: |        |        |********|********|
		^
		j
		w : |   ****|
		^
		bits
		out:|**|**|**|**|**|**|**|**|* |
		^^
		ib
		*/
		unsigned char b = 0;  // bits in out[i] already filled in
		while (b < 8) {
			int nbits = min(8 - b, bits);
			uint16_t mask = (1 << nbits) - 1;
			unsigned char t = (w >> (bits - nbits)) & mask;  // the bits to copy from w to out
			out[i] = out[i] + (t << (8 - b - nbits));
			b += nbits;
			bits -= nbits;
			w &= ~(mask << bits);  // not strictly necessary; mostly for debugging

			if (bits == 0) {
				if (j < inlen) {
					w = in[j];
					bits = lsb;
					j++;
				}
				else {
					break;  // the input vector is exhausted
				}
			}
		}
		if (b == 8) {  // out[i] is filled in
			i++;
		}
	}
}

void unpack(uint16_t *out, const size_t outlen, const unsigned char *in, const size_t inlen, const unsigned char lsb)
{ // Unpack the input char vector into a uint16_t output vector, copying lsb bits
  // for each output element from input. outlen must be at least ceil(inlen * 8 / lsb).
	memset(out, 0, outlen * sizeof(uint16_t));

	size_t i = 0;            // whole uint16_t already filled in
	size_t j = 0;            // whole bytes already copied
	unsigned char w = 0;     // the leftover, not yet copied
	unsigned char bits = 0;  // the number of lsb bits of w

	while (i < outlen && (j < inlen || ((j == inlen) && (bits > 0)))) {
		/*
		in: |  |  |  |  |  |  |**|**|...
		^
		j
		w : | *|
		^
		bits
		out:|   *****|   *****|   ***  |        |...
		^   ^
		i   b
		*/
		unsigned char b = 0;  // bits in out[i] already filled in
		while (b < lsb) {
			int nbits = min(lsb - b, bits);
			uint16_t mask = (1 << nbits) - 1;
			unsigned char t = (w >> (bits - nbits)) & mask;  // the bits to copy from w to out
			out[i] = out[i] + (t << (lsb - b - nbits));
			b += nbits;
			bits -= nbits;
			w &= ~(mask << bits);  // not strictly necessary; mostly for debugging

			if (bits == 0) {
				if (j < inlen) {
					w = in[j];
					bits = 8;
					j++;
				}
				else {
					break;  // the input vector is exhausted
				}
			}
		}
		if (b == lsb) {  // out[i] is filled in
			i++;
		}
	}
}

void clear_words(void* mem, unsigned int nwords)
{ // Clear 32-bit words from memory. "nwords" indicates the number of words to be zeroed.
  // This function uses the volatile type qualifier to inform the compiler not to optimize out the memory clearing.
	volatile uint32_t *v = mem;

	for (unsigned int i = 0; i < nwords; i++) {
		v[i] = 0;
	}
}

void key_encode(uint16_t *out, const uint16_t *in)
{ // Encoding
	unsigned int i, j, npieces_word = 8;
	unsigned int nwords = (PARAMS_NBAR*PARAMS_NBAR) / 8;
	uint64_t temp, mask = ((uint64_t)1 << PARAMS_EXTRACTED_BITS) - 1;
	uint16_t* pos = out;

	for (i = 0; i < nwords; i++) {
		temp = 0;
		for (j = 0; j < PARAMS_EXTRACTED_BITS; j++)
			temp |= ((uint64_t)((uint8_t*)in)[i*PARAMS_EXTRACTED_BITS + j]) << (8 * j);
		for (j = 0; j < npieces_word; j++) {
			*pos = (uint16_t)((temp & mask) << (PARAMS_LOGQ - PARAMS_EXTRACTED_BITS));
			temp >>= PARAMS_EXTRACTED_BITS;
			pos++;
		}
	}
}

void key_decode(uint16_t *out, const uint16_t *in)
{ // Decoding
	unsigned int i, j, index = 0, npieces_word = 8;
	unsigned int nwords = (PARAMS_NBAR * PARAMS_NBAR) / 8;
	uint16_t temp, maskex = ((uint16_t)1 << PARAMS_EXTRACTED_BITS) - 1, maskq = ((uint16_t)1 << PARAMS_LOGQ) - 1;
	uint8_t  *pos = (uint8_t*)out;
	uint64_t templong;

	for (i = 0; i < nwords; i++) {
		templong = 0;
		for (j = 0; j < npieces_word; j++) {  // temp = floor(in*2^{-11}+0.5)
			temp = ((in[index] & maskq) + (1 << (PARAMS_LOGQ - PARAMS_EXTRACTED_BITS - 1))) >> (PARAMS_LOGQ - PARAMS_EXTRACTED_BITS);
			templong |= ((uint64_t)(temp & maskex)) << (PARAMS_EXTRACTED_BITS * j);
			index++;
		}
		for (j = 0; j < PARAMS_EXTRACTED_BITS; j++)
			pos[i*PARAMS_EXTRACTED_BITS + j] = (templong >> (8 * j)) & 0xFF;
	}
}