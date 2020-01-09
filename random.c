/********************************************************************************************
* Hardware-based random number generation function using /dev/urandom
*********************************************************************************************/ 

#include "random.h"
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "config.h"


//#if AlgName == FrodoKEM

static int lock = -1;
static __inline void delay(unsigned int count)
{
	while (count--) {}
}

int randombytes(unsigned char* random_array, unsigned int nbytes)
{ // Generation of "nbytes" of random values

	int r, n = nbytes, count = 0;
    
    if (lock == -1) {
	    do {
		    lock = open("/dev/urandom", O_RDONLY);
		    if (lock == -1) {
			    delay(0xFFFFF);
		    }
	    } while (lock == -1);
    }

	while (n > 0) {
		do {
			r = read(lock, random_array+count, n);
			if (r == -1) {
				delay(0xFFFF);
			}
		} while (r == -1);
		count += r;
		n -= r;
	}

	return 0;
}
//#elif AlgName == Lizard
//
//static int fd = -1;
//
//void randombytes(unsigned char *x, unsigned long long xlen)
//{
//	int i;
//
//	if (fd == -1) {
//		for (;;) {
//			fd = open("/dev/urandom", O_RDONLY);
//			if (fd != -1) break;
//			sleep(1);
//		}
//	}
//
//	while (xlen > 0) {
//		if (xlen < 1048576) i = xlen; else i = 1048576;
//
//		i = read(fd, x, i);
//		if (i < 1) {
//			sleep(1);
//			continue;
//		}
//
//		x += i;
//		xlen -= i;
//	}
//}
//#endif