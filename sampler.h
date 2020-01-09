#ifndef _SAMPLER_H
#define _SAMPLER_H

#include "aes/aes.h"
#include <stdint.h>
#include <stdlib.h>
#include "params.h"
#include "fips202.h"
#include "random.h"
#include <string.h>
#include <stdio.h>


void fill(uint16_t *a_row_temp, int n, int n_bar,int ip);

void fill2(uint16_t *a_row_temp, int n, int n_bar,int ip);

void aes_GenA(uint16_t *a);

void cshake_GenA(uni_t *output, unsigned long long outlen, const unsigned char *seed_A);

void sample_n(uint16_t *s, const size_t n);

uint16_t Sample_Lizard();
#endif
