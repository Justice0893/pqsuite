
//MATEMATÝKSEL ÝÞLEMLER

#include "params.h"
#include <immintrin.h>
#include "sampler.h"
#include "pack.h"
#include "config.h"

int lwe_aspe(uni_t *out, unsigned char *a, uni_t *s, uni_t *e, int n, int nbar, int nbarbar) {
	int i, j, k;
	memcpy(out, e, nbarbar * n * sizeof(uint16_t));

	uint8_t aes_key_schedule[16 * 11];
	AES128_load_schedule(a, aes_key_schedule);
	ALIGN_HEADER(32) uint16_t *A ALIGN_FOOTER(32);
	//A = calloc(PARAMS_N * PARAMS_N, sizeof(uint16_t));
	int l = n % PARAMS_PARALLEL;
	int z = 0;
	A = calloc(nbar * PARAMS_PARALLEL, sizeof(uint16_t));

	for (i = 0; i < n - l; i += PARAMS_PARALLEL) {

		//fill(A+(PARAMS_N*i), PARAMS_N, 4, i);
		//AES128_ECB_enc_sch((uint8_t*)(A + (PARAMS_N*i)), 4 * PARAMS_N * sizeof(int16_t), aes_key_schedule, (uint8_t*)A);

		//A = calloc(PARAMS_N * 4, sizeof(uint16_t));

	#if (Generation == UniformAES)
		fill(A, nbar, PARAMS_PARALLEL, i);
		AES128_ECB_enc_sch((uint8_t*)A, PARAMS_PARALLEL * nbar * sizeof(int16_t), aes_key_schedule, (uint8_t*)A);
	#elif (Generation == UniformCSHAKE)
		for (i = 0; i < PARAMS_N; i++) {
			cshake128_simple((unsigned char*)(a + i * PARAMS_N), (unsigned long long)(2 * PARAMS_N), (uint16_t)(256 + i), a, (unsigned long long)BYTES_SEED_A);
		}
	#endif    
		for (k = 0; k < nbarbar; k++) {
			uint16_t sum[4] = { 0 };
			for (j = 0; j < nbar; j++) {

				/*printf("\ns[%d] = %d\n", k*nbar + j, s[k*nbar + j]);

				printf("A[%d] = %d\n", 0 * (nbar)+j + z, A[0 * (nbar)+j + z]);
				printf("A[%d] = %d\n", 1 * (nbar)+j + z, A[1 * (nbar)+j + z]);
				printf("A[%d] = %d\n", 2 * (nbar)+j + z, A[2 * (nbar)+j + z]);
				printf("A[%d] = %d\n", 3 * (nbar)+j + z, A[3 * (nbar)+j + z]);*/

				uint16_t sp = s[k*nbar + j];
				sum[0] += A[0 * (nbar)+j] * sp;
				sum[1] += A[1 * (nbar)+j] * sp;
				sum[2] += A[2 * (nbar)+j] * sp;
				sum[3] += A[3 * (nbar)+j] * sp;
			}
#if AlgName == FrodoKEM
			out[(i + 0)*nbarbar + k] += sum[0];
			out[(i + 2)*nbarbar + k] += sum[2];
			out[(i + 1)*nbarbar + k] += sum[1];
			out[(i + 3)*nbarbar + k] += sum[3];
#elif AlgName == Lizard
			out[(i + 0)*nbarbar + k] -= sum[0];
			out[(i + 2)*nbarbar + k] -= sum[2];
			out[(i + 1)*nbarbar + k] -= sum[1];
			out[(i + 3)*nbarbar + k] -= sum[3];
#endif
			/*printf("out[%d] = %d\n", (i + 0)*nbarbar + k, out[(i + 0)*nbarbar + k]);
			printf("out[%d] = %d\n", (i + 1)*nbarbar + k, out[(i + 1)*nbarbar + k]);
			printf("out[%d] = %d\n", (i + 2)*nbarbar + k, out[(i + 2)*nbarbar + k]);
			printf("out[%d] = %d\n", (i + 3)*nbarbar + k, out[(i + 3)*nbarbar + k]);*/
		}
		//z += (nbar) * 4;
		clear_words(A, nbar * PARAMS_PARALLEL / 2);

	}

	if (n % 4 != 0) {
		for (int t = 0; t < l*nbarbar; t += nbarbar) {
			for (k = 0; k < nbarbar; k++) {
				uint16_t sum[1] = { 0 };
				for (j = 0; j < nbar; j++) {
					uint16_t sp = s[k*nbar + j];
					sum[0] += a[0 * nbar + j + z] * sp;
				}
				out[i*nbarbar + k + t] += sum[0];
			}
			z += nbar;
		}
	}
	//free(A);
	AES128_free_schedule(aes_key_schedule);
	return 0;
}

int lwe_sape(uni_t *out, const unsigned char *a, uni_t *s, uni_t *e, int n, int nbar, int nbarbar) {


	ALIGN_HEADER(32) uni_t *a_t ALIGN_FOOTER(32);
	ALIGN_HEADER(32) uni_t *A ALIGN_FOOTER(32);

	//a_t = _aligned_malloc(PARAMS_N*PARAMS_N * sizeof(uint16_t), 32);

	memcpy(out, e, nbarbar * nbar * sizeof(uint16_t));

	int l = nbar % 8;
	//int l1 = nbar % 8;
	int kk, i, k, j;

	uint8_t aes_key_schedule[16 * 11];
	AES128_load_schedule(a, aes_key_schedule);

	A = calloc(n * PARAMS_STRIPE_STEP, sizeof(uint16_t));
	a_t = calloc(n * PARAMS_STRIPE_STEP, sizeof(uint16_t));

	/*for (i = 0; i < n; i++) {
		for (k = 0; k < n; k++) {

			a_t[k*n + i] = a[i*n + k];

		}
	}*/

	int z = 0;

	for (kk = 0; kk < nbar - l; kk += PARAMS_STRIPE_STEP) {

		fill2(A, n, PARAMS_STRIPE_STEP, kk);
		AES128_ECB_enc_sch((uint8_t*)A, PARAMS_STRIPE_STEP * n * sizeof(int16_t), aes_key_schedule, (uint8_t*)A);

		for (i = 0; i < n; i++) {
			for (k = 0; k < PARAMS_STRIPE_STEP; k++) {

				a_t[k*n + i] = A[i*PARAMS_STRIPE_STEP + k];

			}
		}

		for (i = 0; i < nbarbar; i++) {
			for (k = 0; k < PARAMS_STRIPE_STEP; k += PARAMS_PARALLEL) {
				uint16_t sum[PARAMS_PARALLEL] = { 0 };
				for (j = 0; j < n; j++) {
					uint16_t sp = s[i*n + j];

					sum[0] += sp * a_t[(k + 0)*(n)+j];
					sum[1] += sp * a_t[(k + 1)*(n)+j];
					sum[2] += sp * a_t[(k + 2)*(n)+j];
					sum[3] += sp * a_t[(k + 3)*(n)+j];

					/*sum[0] += sp * a_t[(kk + k + 0)*(n)+j];
					sum[1] += sp * a_t[(kk + k + 1)*(n)+j];
					sum[2] += sp * a_t[(kk + k + 2)*(n)+j];
					sum[3] += sp * a_t[(kk + k + 3)*(n)+j];*/

					/*printf("s[%d] = %d\n", i*n + j, s[i*n + j]);
					printf("a_t[%d] = %d\n", (k + 0)*(n)+j, a_t[(k + 0)*(n)+j]);
					printf("a_t[%d] = %d\n", (k + 1)*(n)+j, a_t[(k + 1)*(n)+j]);
					printf("a_t[%d] = %d\n", (k + 2)*(n)+j, a_t[(k + 2)*(n)+j]);
					printf("a_t[%d] = %d\n", (k + 3)*(n)+j, a_t[(k + 3)*(n)+j]);*/
				}

				/*out[i*(n)+kk + k + 0] += sum[0];
				out[i*(n)+kk + k + 1] += sum[1];
				out[i*(n)+kk + k + 2] += sum[2];
				out[i*(n)+kk + k + 3] += sum[3];*/

				out[i*(nbar)+kk + k + 0] += sum[0];
				out[i*(nbar)+kk + k + 1] += sum[1];
				out[i*(nbar)+kk + k + 2] += sum[2];
				out[i*(nbar)+kk + k + 3] += sum[3];

				/*printf("out[%d] = %d\n", i*(nbar)+kk + k + 0, out[i*(nbar)+kk + k + 0]);
				printf("out[%d] = %d\n", i*(nbar)+kk + k + 1, out[i*(nbar)+kk + k + 1]);
				printf("out[%d] = %d\n", i*(nbar)+kk + k + 2, out[i*(nbar)+kk + k + 2]);
				printf("out[%d] = %d\n", i*(nbar)+kk + k + 3, out[i*(nbar)+kk + k + 3]);*/
			}
		}
		//z += n * PARAMS_STRIPE_STEP;
		clear_words(A, n * PARAMS_STRIPE_STEP / 2);
		clear_words(a_t, n * PARAMS_STRIPE_STEP / 2);
		//clear_words(a_t, PARAMS_N * 4);
	}
	k = n - (n % 8);
	if (n % 8 != 0) {
		for (int t = 0; t < l; t += 1) {
			k = k + t;
			for (i = 0; i < nbarbar; i++) {
				uint16_t sum[1] = { 0 };
				for (j = 0; j < n; j++) {
					uint16_t sp = s[i*n + j];
					sum[0] += sp * a_t[j + z];
				}
				out[k] += sum[0];
				k += n;
			}
			k = n - (n % 8);
			z += n;
		}
	}
	//_aligned_free(a_t);
	return 0;
}

int lwe_sape_deneme(uni_t *out, uni_t *a, uni_t *s, uni_t *e, int n, int nbar, int nbarbar) {


	ALIGN_HEADER(32) uni_t a_t[PARAMS_N*PARAMS_N] ALIGN_FOOTER(32);

	//a_t = _aligned_malloc(PARAMS_N*PARAMS_N * sizeof(uint16_t), 32);

	memcpy(out, e, nbarbar * n * sizeof(uint16_t));

	int l = nbar % 8;
	//int l1 = nbar % 8;
	int kk, i, k, j;

	for (i = 0; i < n; i++) {
		for (k = 0; k < nbar; k++) {

			a_t[k*n + i] = a[i*nbar + k];

		}
	}

	int z = 0;

	for (kk = 0; kk < nbar - l; kk += PARAMS_STRIPE_STEP) {

		for (i = 0; i < nbarbar; i++) {
			for (k = 0; k < PARAMS_STRIPE_STEP; k += PARAMS_PARALLEL) {
				uint16_t sum[PARAMS_PARALLEL] = { 0 };
				for (j = 0; j < n; j++) {
					uint16_t sp = s[i*n + j];

					sum[0] += sp * a_t[(kk + k + 0)*(n)+j];
					sum[1] += sp * a_t[(kk + k + 1)*(n)+j];
					sum[2] += sp * a_t[(kk + k + 2)*(n)+j];
					sum[3] += sp * a_t[(kk + k + 3)*(n)+j];

					/*sum[0] += sp * a_t[(k + 0)*(n)+j + z];
					sum[1] += sp * a_t[(k + 1)*(n)+j + z];
					sum[2] += sp * a_t[(k + 2)*(n)+j + z];
					sum[3] += sp * a_t[(k + 3)*(n)+j + z];*/

					//printf("s[%d] = %d\n", i*n + j, s[i*n + j]);
					//printf("a_t[%d] = %d\n", (k + 0)*(n)+j + z, a_t[(k + 0)*(n)+j + z]);
					//printf("a_t[%d] = %d\n", (k + 1)*(n)+j + z, a_t[(k + 1)*(n)+j + z]);
					//printf("a_t[%d] = %d\n", (k + 2)*(n)+j + z, a_t[(k + 2)*(n)+j + z]);
					//printf("a_t[%d] = %d\n", (k + 3)*(n)+j + z, a_t[(k + 3)*(n)+j + z]);
				}

				/*out[i*(n)+kk + k + 0] += sum[0];
				out[i*(n)+kk + k + 1] += sum[1];
				out[i*(n)+kk + k + 2] += sum[2];
				out[i*(n)+kk + k + 3] += sum[3];*/

				out[i*(nbar)+kk + k + 0] += sum[0];
				out[i*(nbar)+kk + k + 1] += sum[1];
				out[i*(nbar)+kk + k + 2] += sum[2];
				out[i*(nbar)+kk + k + 3] += sum[3];

				//printf("out[%d] = %d\n", i*(n)+kk + k + 0, out[i*(n)+kk + k + 0]);
				//printf("out[%d] = %d\n", i*(n)+kk + k + 1, out[i*(n)+kk + k + 1]);
				//printf("out[%d] = %d\n", i*(n)+kk + k + 2, out[i*(n)+kk + k + 2]);
				//printf("out[%d] = %d\n", i*(n)+kk + k + 3, out[i*(n)+kk + k + 3]);
			}
		}
		//z += n * PARAMS_STRIPE_STEP;
	}
	k = n - (n % 8);
	if (n % 8 != 0) {
		for (int t = 0; t < l; t += 1) {
			k = k + t;
			for (i = 0; i < nbarbar; i++) {
				uint16_t sum[1] = { 0 };
				for (j = 0; j < n; j++) {
					uint16_t sp = s[i*n + j];
					sum[0] += sp * a_t[j + z];
				}
				out[k] += sum[0];
				k += n;
			}
			k = n - (n % 8);
			z += n;
		}
	}
	//_aligned_free(a_t);
	return 0;
}

int lwe_sape_simd(uni_t *out, uni_t *a, uni_t *s, uni_t *e, int n, int nbar, int nbarbar) {
	if (n != nbar)
		return -1;

	ALIGN_HEADER(32) uni_t a_t[PARAMS_N*PARAMS_N] ALIGN_FOOTER(32) = { 0 };
	//a_t = _aligned_malloc(PARAMS_N*PARAMS_N * sizeof(uint16_t), 32);

	memcpy(out, e, nbarbar * n * sizeof(uint16_t));

	int i, kk, k, j;

	for (i = 0; i < n; i++) {
		for (k = 0; k < n; k++) {

			a_t[k*n + i] = a[i*n + k];

		}
	}

	int l = n % 16;
	//int l1 = nbar % 16;
	int z = 0;
	int f = n - (n % 16);
	int y = n - (n % 16);
	for (kk = 0; kk < n - l; kk += PARAMS_STRIPE_STEP) {
		for (i = 0; i < nbarbar; i++) {
			for (k = 0; k < PARAMS_STRIPE_STEP; k += PARAMS_PARALLEL) {
				ALIGN_HEADER(32) uint32_t sum[8 * PARAMS_PARALLEL] ALIGN_FOOTER(32);
				__m256i a[PARAMS_PARALLEL], b, acc[PARAMS_PARALLEL];
				acc[0] = _mm256_setzero_si256();
				acc[1] = _mm256_setzero_si256();
				acc[2] = _mm256_setzero_si256();
				acc[3] = _mm256_setzero_si256();
				for (j = 0; j < n - l; j += 16) {
					b = _mm256_load_si256((__m256i*)&s[i*(n)+j]);
					a[0] = _mm256_load_si256((__m256i*)&a_t[(k + 0)*(n)+j + z]);
					a[0] = _mm256_madd_epi16(a[0], b);
					acc[0] = _mm256_add_epi16(a[0], acc[0]);
					a[1] = _mm256_load_si256((__m256i*)&a_t[(k + 1)*(n)+j + z]);
					a[1] = _mm256_madd_epi16(a[1], b);
					acc[1] = _mm256_add_epi16(a[1], acc[1]);
					a[2] = _mm256_load_si256((__m256i*)&a_t[(k + 2)*(n)+j + z]);
					a[2] = _mm256_madd_epi16(a[2], b);
					acc[2] = _mm256_add_epi16(a[2], acc[2]);
					a[3] = _mm256_load_si256((__m256i*)&a_t[(k + 3)*(n)+j + z]);
					a[3] = _mm256_madd_epi16(a[3], b);
					acc[3] = _mm256_add_epi16(a[3], acc[3]);
				}
				_mm256_store_si256((__m256i*)(sum + (8 * 0)), acc[0]);
				out[i*(n)+kk + k + 0] += sum[8 * 0 + 0] + sum[8 * 0 + 1] + sum[8 * 0 + 2] + sum[8 * 0 + 3] + sum[8 * 0 + 4] + sum[8 * 0 + 5] + sum[8 * 0 + 6] + sum[8 * 0 + 7];
				_mm256_store_si256((__m256i*)(sum + (8 * 1)), acc[1]);
				out[i*(n)+kk + k + 1] += sum[8 * 1 + 0] + sum[8 * 1 + 1] + sum[8 * 1 + 2] + sum[8 * 1 + 3] + sum[8 * 1 + 4] + sum[8 * 1 + 5] + sum[8 * 1 + 6] + sum[8 * 1 + 7];
				_mm256_store_si256((__m256i*)(sum + (8 * 2)), acc[2]);
				out[i*(n)+kk + k + 2] += sum[8 * 2 + 0] + sum[8 * 2 + 1] + sum[8 * 2 + 2] + sum[8 * 2 + 3] + sum[8 * 2 + 4] + sum[8 * 2 + 5] + sum[8 * 2 + 6] + sum[8 * 2 + 7];
				_mm256_store_si256((__m256i*)(sum + (8 * 3)), acc[3]);
				out[i*(n)+kk + k + 3] += sum[8 * 3 + 0] + sum[8 * 3 + 1] + sum[8 * 3 + 2] + sum[8 * 3 + 3] + sum[8 * 3 + 4] + sum[8 * 3 + 5] + sum[8 * 3 + 6] + sum[8 * 3 + 7];

				if (n % 16 != 0) {
					uint16_t sum[4] = { 0 };
					for (int r = 0; r < l; r++) {
						uint16_t sp = s[y + r];

						sum[0] += sp * a_t[f + r + z];
						sum[1] += sp * a_t[f + n + r + z];
						sum[2] += sp * a_t[f + 2 * n + r + z];
						sum[3] += sp * a_t[f + 3 * n + r + z];
					}

					out[i*(n)+kk + k + 0] += sum[0];
					out[i*(n)+kk + k + 1] += sum[1];
					out[i*(n)+kk + k + 2] += sum[2];
					out[i*(n)+kk + k + 3] += sum[3];

					f += 4 * n;
				}
			}
			y += n;
			f = n - (n % 16);
		}
		z += n * PARAMS_STRIPE_STEP;
		y = n - (n % 16);
	}

	if (n % 16 != 0) {
		int f = n - (n % 16);
		int t = f;

		for (i = 0; i < nbarbar; i++) {
			z = n * (n - n % 16);
			for (k = 0; k < l; k += 1) {
				ALIGN_HEADER(32) uint32_t sum[8] ALIGN_FOOTER(32);
				__m256i a[1], b, acc[1];
				acc[0] = _mm256_setzero_si256();
				for (j = 0; j < n - l; j += 16) {
					b = _mm256_load_si256((__m256i*)&s[i*(n)+j]);
					a[0] = _mm256_load_si256((__m256i*)&a_t[j + z]);
					a[0] = _mm256_madd_epi16(a[0], b);
					acc[0] = _mm256_add_epi16(a[0], acc[0]);
				}
				_mm256_store_si256((__m256i*)(sum + (8 * 0)), acc[0]);
				out[f] += sum[8 * 0 + 0] + sum[8 * 0 + 1] + sum[8 * 0 + 2] + sum[8 * 0 + 3] + sum[8 * 0 + 4] + sum[8 * 0 + 5] + sum[8 * 0 + 6] + sum[8 * 0 + 7];

				uint16_t sum1[1] = { 0 };
				for (int r = 0; r < l; r++) {
					uint16_t sp = s[y + r];
					sum1[0] += sp * a_t[z + t + r];

				}
				out[f] += sum1[0];
				f += 1;
				if (l > 2) {
					z += n;
					continue;
				}
				z += (l - 1)* n;
			}
			y += n;
			f += (n - n % 16);
		}
	}
	//_aligned_free(a_t);
	return 0;
}

void lwe_add(uint16_t *out, const uint16_t *a, const uint16_t *b)
{
	for (int i = 0; i < (PARAMS_NBAR*PARAMS_NBAR); i++) {
		out[i] = (a[i] + b[i]) & ((1 << PARAMS_LOGQ) - 1);
	}
}

void lwe_mul_bs(uint16_t *out, const uint16_t *b, const uint16_t *s)
{ // Multiply by s on the right
  // Inputs: b (N_BAR x NPRIME), s (NPRIME x N_BAR)
  // Output: out = b*s (N_BAR x N_BAR)
	int i, j, k;

	for (i = 0; i < PARAMS_NBAR; i++) {
		for (j = 0; j < PARAMS_NBAR; j++) {
			out[i*PARAMS_NBAR + j] = 0;
			for (k = 0; k < PARAMS_NPRIME; k++) {
				out[i*PARAMS_NBAR + j] += b[i*PARAMS_NPRIME + k] * s[j*PARAMS_NPRIME + k];
			}
			out[i*PARAMS_NBAR + j] = (uint32_t)(out[i*PARAMS_NBAR + j]) & ((1 << PARAMS_LOGQ) - 1);
		}
	}
}

void lwe_sub(uint16_t *out, const uint16_t *a, const uint16_t *b)
{ // Subtract a and b
  // Inputs: a, b (N_BAR x N_BAR)
  // Output: c = a - b

	for (int i = 0; i < (PARAMS_NBAR*PARAMS_NBAR); i++) {
		out[i] = (a[i] - b[i]) & ((1 << PARAMS_LOGQ) - 1);
	}
}

void lwe_mul_add_sb_plus_e(uint16_t *out, const uint16_t *b, const uint16_t *s, const uint16_t *e)
{ // Multiply by s on the left
  // Inputs: b (N x N_BAR), s (N_BAR x N), e (N_BAR x N_BAR)
  // Output: out = s*b + e (N_BAR x N_BAR)
	int i, j, k;

	for (k = 0; k < PARAMS_NBAR; k++) {
		for (i = 0; i < PARAMS_NBAR; i++) {
			out[k*PARAMS_NBAR + i] = e[k*PARAMS_NBAR + i];
			for (j = 0; j < PARAMS_N; j++) {
				out[k*PARAMS_NBAR + i] += s[k*PARAMS_N + j] * b[j*PARAMS_NBAR + i];
			}
			out[k*PARAMS_NBAR + i] = (uint32_t)(out[k*PARAMS_NBAR + i]) & ((1 << PARAMS_LOGQ) - 1);
		}
	}
}