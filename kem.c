
//PROTOKOLLERÝN GENEL YAPISI ÝÇÝNDEKÝ KODLAR


#include "sampler.h"
#include "pack.h"
#include "lwe.h"
#include "params.h"
#include "config.h"

int crypto_kem_keypair(unsigned char* pk, unsigned char* sk)
{
	//uni_t A[(((PARAMS_N + 15) >> 4) << 4)*(((PARAMS_N + 15) >> 4) << 4)] = { 0 };
	uint16_t B[PARAMS_N*PARAMS_NBAR] = { 0 }, S[(PARAMS_NPRIME + PARAMS_N)*PARAMS_NBAR + (PARAMS_L / 8)] = { 0 };
	uint16_t *E = (uint16_t *)&S[PARAMS_NPRIME*PARAMS_NBAR];
	uint8_t *randomness = sk;


	// Generate the secret value s, the seed for S and E, and the seed for A. Add seed_A to the public key
	randombytes(randomness, 2 * CRYPTO_BYTES + BYTES_SEED_A);
	cshake128_simple(pk, BYTES_SEED_A, 0, randomness + 2 * CRYPTO_BYTES, (unsigned long long)(BYTES_SEED_A));

#if (AlgName == Lizard && ParSet == Set1)
	randombytes(S, PARAMS_NPRIME * PARAMS_NBAR);
	for (int i = 0; i < PARAMS_NPRIME * PARAMS_NBAR; ++i) {
		if ((S[i] & 0x03) == 0x00)
			S[i] = -1;
		else if ((S[i] & 0x03) == 0x01)
			S[i] = 1;
		else
			S[i] = 0;
	}
		cshake128_simple((uint8_t*)(S + (PARAMS_NPRIME*PARAMS_NBAR)), PARAMS_N*PARAMS_NBAR * sizeof(uni_t), 1, randomness + CRYPTO_BYTES, (unsigned long long)(CRYPTO_BYTES));
		sample_n(E, PARAMS_N*PARAMS_NBAR);
		randombytes(S + PARAMS_NPRIME * PARAMS_NBAR, (PARAMS_NBAR / 8)); // T eklemesi

#elif (AlgName == Lizard && ParSet == Set2)
	randombytes(S, PARAMS_NPRIME * PARAMS_NBAR);
	for (i = 0; i < PARAMS_NPRIME * PARAMS_NBAR; ++i) {
		if ((S[i] & 0x07) == 0x00)
			S[i] = -1;
		else if ((S[i] & 0x07) == 0x01)
			S[i] = 1;
		else
			S[i] = 0;

		cshake128_simple((uint8_t*)(S + (PARAMS_NPRIME*PARAMS_NBAR)), PARAMS_N*PARAMS_NBAR * sizeof(uni_t), 1, randomness + CRYPTO_BYTES, (unsigned long long)(CRYPTO_BYTES));
		sample_n(E, PARAMS_N*PARAMS_NBAR);
		randombytes(S + PARAMS_N * (PARAMS_NPRIME+PARAMS_NBAR), (PARAMS_NBAR / 8)); // T eklemesi

	}

#elif AlgName == FrodoKEM

	// Generate S and E, and compute B = A*S + E. Generate A on-the-fly
	cshake128_simple((uint8_t*)S, (PARAMS_NPRIME + PARAMS_N)*PARAMS_NBAR * sizeof(uni_t), 1, randomness + CRYPTO_BYTES, (unsigned long long)(CRYPTO_BYTES));
	sample_n(S, PARAMS_NPRIME*PARAMS_NBAR);
	sample_n(E, PARAMS_N*PARAMS_NBAR);

#endif

	lwe_aspe(B, pk, S, E, PARAMS_N, PARAMS_NPRIME, PARAMS_NBAR);

	// Encode the second part of the public key
	pack(pk + BYTES_SEED_A, CRYPTO_PUBLICKEYBYTES - BYTES_SEED_A, B, PARAMS_N*PARAMS_NBAR, PARAMS_LOGQ);

#if AlgName == FrodoKEM
	// Add pk and S to the secret key
	memcpy(&sk[CRYPTO_BYTES], pk, CRYPTO_PUBLICKEYBYTES);
	memcpy(&sk[CRYPTO_BYTES + CRYPTO_PUBLICKEYBYTES], S, (PARAMS_NPRIME + PARAMS_N)*PARAMS_NBAR);
#endif
	// Cleanup:
	clear_words((void*)S, (PARAMS_NPRIME*PARAMS_NBAR+PARAMS_L/8) / 2);
	clear_words((void*)E, PARAMS_N*PARAMS_NBAR / 2);
	return 0;
}

int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
{ // Frodo-KEM's key encapsulation

	//uni_t A[(((PARAMS_N + 15) >> 4) << 4)*(((PARAMS_N + 15) >> 4) << 4)] = { 0 };
	unsigned char randomness[BYTES_MU];
	uint16_t B[PARAMS_N*PARAMS_NBARBAR] = { 0 }, V[PARAMS_NBARBAR*PARAMS_NBARBAR] = { 0 }, C[PARAMS_NBARBAR*PARAMS_NBARBAR] = { 0 };
	ALIGN_HEADER(32) uint16_t Bp[PARAMS_NPRIME*PARAMS_NBARBAR] ALIGN_FOOTER(32) = { 0 };
	ALIGN_HEADER(32) uint16_t Sp[(PARAMS_NPRIME + PARAMS_N + PARAMS_NBARBAR)*PARAMS_NBARBAR] ALIGN_FOOTER(32) = { 0 };
	uint16_t *Ep = (uint16_t *)&Sp[PARAMS_N*PARAMS_NBARBAR];
	uint16_t *Epp = (uint16_t *)&Sp[(PARAMS_NPRIME + PARAMS_N)*PARAMS_NBARBAR];
	uint8_t temp[TEMP_BYTES], G[3 * CRYPTO_BYTES];

	// temp <- pk||mu, and generate (r||KK||d) = G(pk||mu)
	randombytes(randomness, BYTES_MU);
	memcpy(temp, pk, CRYPTO_PUBLICKEYBYTES);
	memcpy(&temp[CRYPTO_PUBLICKEYBYTES], randomness, BYTES_MU);
	cshake128_simple(G, 3 * CRYPTO_BYTES, 2, temp, (unsigned long long)(CRYPTO_PUBLICKEYBYTES + BYTES_MU));

	// Generate Sp and Ep, and compute Bp = Sp*A + Ep. Generate A on-the-fly
	cshake128_simple((uint8_t*)Sp, (PARAMS_N + PARAMS_NPRIME + PARAMS_NBAR)*PARAMS_NBARBAR * sizeof(uni_t), 3, G, (unsigned long long)(CRYPTO_BYTES));
	sample_n(Sp, PARAMS_N*PARAMS_NBARBAR);
	sample_n(Ep, PARAMS_NPRIME*PARAMS_NBARBAR);

	//uint8_t aes_key_schedule[16 * 11];
	//AES128_load_schedule(pk, aes_key_schedule);
	//fill(A, PARAMS_N, PARAMS_NPRIME,0);
	//AES128_ECB_enc_sch((uint8_t*)A, (((PARAMS_N + 15) >> 4) << 4) * PARAMS_NPRIME * sizeof(int16_t), aes_key_schedule, (uint8_t*)A);

	//frodo_mul_add_sa_plus_e(Bp, Sp, Ep, temp);
	lwe_sape(Bp, pk, Sp, Ep, PARAMS_N, PARAMS_NPRIME, PARAMS_NBARBAR);
	//lwe_sape_simd(Bp, A, Sp, Ep, PARAMS_N, PARAMS_NPRIME, PARAMS_NBAR);
	//lwe_sape_deneme(Bp, A, Sp, Ep, PARAMS_N, PARAMS_NPRIME, PARAMS_NBAR);

	pack(ct, (PARAMS_LOGQ*PARAMS_NPRIME*PARAMS_NBARBAR) / 8, Bp, PARAMS_NPRIME*PARAMS_NBARBAR, PARAMS_LOGQ);

	// Generate Epp, and compute V = Sp*B + Epp
	sample_n(Epp, PARAMS_NBARBAR*PARAMS_NBARBAR);
	unpack(B, PARAMS_N*PARAMS_NBARBAR, temp + BYTES_SEED_A, CRYPTO_PUBLICKEYBYTES - BYTES_SEED_A, PARAMS_LOGQ);
	lwe_mul_add_sb_plus_e(V, B, Sp, Epp);

	// Encode mu, and compute C = V + enc(mu) (mode q)
	key_encode(C, (uni_t*)(temp + CRYPTO_PUBLICKEYBYTES));
	lwe_add(C, V, C);
	pack(ct + (PARAMS_LOGQ*PARAMS_NPRIME*PARAMS_NBARBAR) / 8, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBARBAR) / 8, C, PARAMS_NBARBAR*PARAMS_NBARBAR, PARAMS_LOGQ);

	// Compute ss = F(ct||KK||d) and the ciphertext CT = ct||d
	memcpy(temp, ct, CRYPTO_CIPHERTEXTBYTES - CRYPTO_BYTES);
	memcpy(&temp[CRYPTO_CIPHERTEXTBYTES - CRYPTO_BYTES], &G[CRYPTO_BYTES], 2 * CRYPTO_BYTES);
	cshake128_simple(ss, CRYPTO_BYTES, 4, temp, (unsigned long long)(CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES));
	memcpy(&ct[CRYPTO_CIPHERTEXTBYTES - CRYPTO_BYTES], &G[2 * CRYPTO_BYTES], CRYPTO_BYTES);

	// Cleanup:
	clear_words((void*)Sp, PARAMS_N*PARAMS_NBARBAR / 2);
	clear_words((void*)Ep, PARAMS_NPRIME*PARAMS_NBARBAR / 2);
	clear_words((void*)Epp, PARAMS_NBARBAR*PARAMS_NBARBAR / 2);
	clear_words((void*)V, PARAMS_NBARBAR*PARAMS_NBARBAR / 2);
	clear_words((void*)G, CRYPTO_BYTES / 2);
	clear_words((void*)(temp + CRYPTO_CIPHERTEXTBYTES - CRYPTO_BYTES), CRYPTO_BYTES / 2);
	return 0;
}

int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{ // Frodo-KEM's key decapsulation
	//uni_t A[(((PARAMS_N + 15) >> 4) << 4)*(((PARAMS_N + 15) >> 4) << 4)] = { 0 };
	uint16_t B[PARAMS_N*PARAMS_NBAR] = { 0 }, Bp[PARAMS_NPRIME*PARAMS_NBAR] = { 0 }, W[PARAMS_NBAR*PARAMS_NBAR] = { 0 };
	uint16_t C[PARAMS_NBAR*PARAMS_NBAR] = { 0 }, CC[PARAMS_NBAR*PARAMS_NBAR] = { 0 };
	uint16_t *S = (uint16_t*)(sk + CRYPTO_BYTES + CRYPTO_PUBLICKEYBYTES);
	ALIGN_HEADER(32) uint16_t BBp[PARAMS_NPRIME*PARAMS_NBAR] ALIGN_FOOTER(32) = { 0 };
	ALIGN_HEADER(32) uint16_t Sp[(PARAMS_NPRIME + PARAMS_N + PARAMS_NBAR)*PARAMS_NBAR] ALIGN_FOOTER(32) = { 0 };
	uint16_t *Ep = (uint16_t *)&Sp[PARAMS_N*PARAMS_NBAR];
	uint16_t *Epp = (uint16_t *)&Sp[(PARAMS_NPRIME + PARAMS_N)*PARAMS_NBAR];
	uint8_t temp[TEMP_BYTES], G[3 * CRYPTO_BYTES], *seed_A = temp;

	// temp <- pk
	memcpy(temp, &sk[CRYPTO_BYTES], CRYPTO_PUBLICKEYBYTES);

	// Compute W = C - Bp*S (mod q), and decode the randomness mu
	unpack(Bp, PARAMS_NPRIME*PARAMS_NBAR, ct, (PARAMS_LOGQ*PARAMS_NPRIME*PARAMS_NBAR) / 8, PARAMS_LOGQ);
	unpack(C, PARAMS_NBAR*PARAMS_NBAR, ct + (PARAMS_LOGQ*PARAMS_NPRIME*PARAMS_NBAR) / 8, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR) / 8, PARAMS_LOGQ);
	lwe_mul_bs(W, Bp, S);
	lwe_sub(W, C, W);
	key_decode((uni_t*)(temp + CRYPTO_PUBLICKEYBYTES), W);

	// Generate (r||KK||d) = G(pk||mu)
	cshake128_simple(G, 3 * CRYPTO_BYTES, 2, temp, (unsigned long long)(CRYPTO_PUBLICKEYBYTES + BYTES_MU));

	//uint8_t aes_key_schedule[16 * 11];
	//AES128_load_schedule(temp, aes_key_schedule);
	//fill(A, PARAMS_N, PARAMS_NPRIME,0);
	//AES128_ECB_enc_sch((uint8_t*)A, (((PARAMS_N + 15) >> 4) << 4) * PARAMS_NPRIME * sizeof(int16_t), aes_key_schedule, (uint8_t*)A);

	// Generate Sp and Ep, and compute BBp = Sp*A + Ep. Generate A on-the-fly
	cshake128_simple((uint8_t*)Sp, (PARAMS_N + PARAMS_NPRIME + PARAMS_NBAR)*PARAMS_NBAR * sizeof(uni_t), 3, G, (unsigned long long)(CRYPTO_BYTES));
	sample_n(Sp, PARAMS_N*PARAMS_NBAR);
	sample_n(Ep, PARAMS_NPRIME*PARAMS_NBAR);
	//frodo_mul_add_sa_plus_e(BBp, Sp, Ep, seed_A);
	//lwe_sape_deneme(BBp, A, Sp, Ep, PARAMS_N, PARAMS_NPRIME,PARAMS_NBAR);
	lwe_sape(BBp, temp, Sp, Ep, PARAMS_N, PARAMS_NPRIME, PARAMS_NBAR);
	//lwe_sape_simd(BBp, A, Sp, Ep, PARAMS_N, PARAMS_NPRIME, PARAMS_NBAR);

	// Generate Epp, and compute W = Sp*B + Epp
	sample_n(Epp, PARAMS_NBAR*PARAMS_NBAR);
	unpack(B, PARAMS_N*PARAMS_NBAR, temp + BYTES_SEED_A, CRYPTO_PUBLICKEYBYTES - BYTES_SEED_A, PARAMS_LOGQ);
	lwe_mul_add_sb_plus_e(W, B, Sp, Epp);

	// Encode mu, and compute CC = W + enc(mu) (mode q)
	key_encode(CC, (uni_t*)(temp + CRYPTO_PUBLICKEYBYTES));
	lwe_add(CC, W, CC);

	// temp <- ct
	memcpy(temp, ct, CRYPTO_CIPHERTEXTBYTES - CRYPTO_BYTES);

	// Reducing BBp modulo q
	for (int i = 0; i < PARAMS_NPRIME*PARAMS_NBAR; i++) BBp[i] = BBp[i] & ((1 << PARAMS_LOGQ) - 1);

	// Is (dd == d & Bp == BBp & C == CC) = true
	if (memcmp(G + 2 * CRYPTO_BYTES, ct + CRYPTO_CIPHERTEXTBYTES - CRYPTO_BYTES, CRYPTO_BYTES) == 0 &&
		memcmp(Bp, BBp, 2 * PARAMS_NPRIME*PARAMS_NBAR) == 0 &&
		memcmp(C, CC, 2 * PARAMS_NBAR*PARAMS_NBAR) == 0) {  // Load (KK || d) to do ss = F(ct||KK||d)
		memcpy(&temp[CRYPTO_CIPHERTEXTBYTES - CRYPTO_BYTES], &G[CRYPTO_BYTES], 2 * CRYPTO_BYTES);
	}
	else {  // Load (s || d) to do ss = F(ct||s||d)
		memcpy(&temp[CRYPTO_CIPHERTEXTBYTES - CRYPTO_BYTES], sk, CRYPTO_BYTES);
		memcpy(&temp[CRYPTO_CIPHERTEXTBYTES], &G[2 * CRYPTO_BYTES], CRYPTO_BYTES);
	}
	cshake128_simple(ss, CRYPTO_BYTES, 4, temp, (unsigned long long)(CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES));

	// Cleanup:
	clear_words((void*)Sp, PARAMS_N*PARAMS_NBAR / 2);
	clear_words((void*)Ep, PARAMS_NPRIME*PARAMS_NBAR / 2);
	clear_words((void*)Epp, PARAMS_NBAR*PARAMS_NBAR / 2);
	clear_words((void*)W, PARAMS_NBAR*PARAMS_NBAR / 2);
	clear_words((void*)G, CRYPTO_BYTES / 2);
	clear_words((void*)(temp + CRYPTO_CIPHERTEXTBYTES - CRYPTO_BYTES), CRYPTO_BYTES / 2);
	return 0;
}