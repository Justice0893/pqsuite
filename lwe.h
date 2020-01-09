#ifndef _LWE_H
#define _LWE_H

int lwe_aspe(uni_t *out, unsigned char *a, uni_t *s, uni_t *e, int n, int nbar, int nbarbar);

int lwe_sape(uni_t *out, const unsigned char *a, uni_t *s, uni_t *e, int n, int nbar, int nbarbar);

int lwe_sape_deneme(uni_t *out, uni_t *a, uni_t *s, uni_t *e, int n, int nbar, int nbarbar);

int lwe_sape_simd(uni_t *out, uni_t *a, uni_t *s, uni_t *e, int n, int nbar, int nbarbar);

void lwe_add(uint16_t *out, const uint16_t *a, const uint16_t *b);

void lwe_mul_bs(uint16_t *out, const uint16_t *b, const uint16_t *s);

void lwe_sub(uint16_t *out, const uint16_t *a, const uint16_t *b);

void lwe_mul_add_sb_plus_e(uint16_t *out, const uint16_t *b, const uint16_t *s, const uint16_t *e);

#endif