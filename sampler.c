
//PROTOKOLLERDEKÝ MATRÝSLERÝ ÜRETMEK ÝÇÝN KULLANILAN TABLOLAR VE BAZI KODLAR
//AYRIK GAUSS DAÐILIMI

#include "sampler.h"
#include "config.h"

//int16_t a_row_temp[PARAMS_N * PARAMS_N] = { 0 };

// CDF table
#if AlgName == FrodoKEM
#if ParSet == Set1
uni_t CDF_TABLE[12] = { 4727, 13584, 20864, 26113, 29434, 31278, 32176, 32560, 32704, 32751, 32764, 32767 };
uni_t CDF_TABLE_LEN = 12;
#elif ParSet == Set2
uint16_t CDF_TABLE[11] = { 5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, 32767 };
uint16_t CDF_TABLE_LEN = 11;
#elif ParSet == Set3
uint16_t CDF_TABLE[7] = { 9142, 23462, 30338, 32361, 32725, 32765, 32767 };
uint16_t CDF_TABLE_LEN = 7;
#endif
#elif AlgName == Lizard
#if ParSet == Set1
const uint16_t CDF_TABLE[9] = { 78, 226, 334, 425, 473, 495, 506, 510, 511 }; // out of [0, 511]
const size_t CDF_TABLE_LEN = 9;
#endif
#endif

void fill(uint16_t *a_row_temp, int n, int n_bar, int ip) {

	int i, j;
	for (i = 0; i < n_bar; i++) {
		for (j = 0; j < n; j += PARAMS_STRIPE_STEP) {
			a_row_temp[(j + 1) + i * n] = j;
			a_row_temp[j + i * n] = i + ip;
			//printf("ii = %d j = %d i = %d\n", ii,j,i);
			//printf("a[%d] = %d\n", (j + 1) + i * n, a_row_temp[(j + 1) + i * n]);
			//printf("a[%d] = %d\n", j + i * n, a_row_temp[j + i * n]);

		}
	}
}

void fill2(uint16_t *a_row_temp, int n, int n_bar, int ip) {

	int i, j;
	for (i = 0, j = 0; i < n; i++, j += n_bar) {
		a_row_temp[j] = i;
	}

	for (i = 0; i < (n*n_bar); i += n_bar) {
		a_row_temp[i + 1] = ip;
	}
}

//#if AlgName == FrodoKEM 
void sample_n(uint16_t *s, const size_t n)
{ // Fills vector s with n samples from the noise distribution which requires 16 bits to sample. 
  // The distribution is specified by its CDF.
  // Input: pseudo-random values (2*n bytes) passed in s. The input is overwritten by the output.
	unsigned int i, j;

	for (i = 0; i < n; ++i) {
		uint8_t sample = 0;
		uint16_t prnd = s[i] >> 1;    // Drop the least significant bit
		uint8_t sign = s[i] & 0x1;    // Pick the least significant bit

									  // No need to compare with the last value.
		for (j = 0; j < (unsigned int)(CDF_TABLE_LEN - 1); j++) {
			// Constant time comparison: 1 if CDF_TABLE[j] < s, 0 otherwise. Uses the fact that CDF_TABLE[j] and s fit in 15 bits.
			sample += (uint16_t)(CDF_TABLE[j] - prnd) >> 15;
		}
		// Assuming that sign is either 0 or 1, flips sample iff sign = 1
		s[i] = ((-sign) ^ sample) + sign;
	}
}

//#elif AlgName == Lizard
//uint16_t sample_n() {
//	uint16_t rnd = seed[count == PARAMS_N * PARAMS_NBAR * 2 ? count = 0 : count++] & 0x01ff;
//	uint16_t sign = seed[count == PARAMS_N * PARAMS_NBAR * 2 ? count = 0 : count++] & 0x01;
//	uint16_t sample = 0;
//	for (size_t i = 0; i < CDF_TABLE_LEN - 1; ++i) {
//		sample += (CDF_TABLE[i] - rnd) >> 15;
//	}
//	sample = ((-sign) ^ sample) + sign;
//	return sample;
//}
//#endif