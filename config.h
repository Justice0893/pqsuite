//SÝSTEM PARAMETRELERÝS

#ifndef _CONFIG_H
#define _CONFIG_H
#include <stdint.h>


typedef uint16_t uni_t;

#define BoundedDiscGaussian 1
#define CenteredBinomial 2
#define Gaussian 3

#define UniformCSHAKE 1
#define UniformAES 2

#define FrodoKEM 0x010
#define Lizard 0x020

#define Set1 1
#define Set2 2
#define Set3 3


#define AlgName (FrodoKEM)
#define ParSet (Set1)

#define Generation (UniformAES)

#if defined(WINDOWS)
    #define ALIGN_HEADER(N) __declspec(align(N))
    #define ALIGN_FOOTER(N) 
#else
    #define ALIGN_HEADER(N)
    #define ALIGN_FOOTER(N) __attribute__((aligned(N)))
#endif
#endif
