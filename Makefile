CC=gcc

AR=ar rcs
RANLIB=ranlib

CFLAGS= -O3 -g -Wall -Wextra -march=native
LDFLAGS=-lm
ifeq "$(USE_OPENSSL)" "TRUE"
LDFLAGS += -L/usr/lib -lssl -lcrypto
endif
ifeq "$(USE_AES_NI)" "TRUE"
CFLAGS += -maes
endif

OBJS = kem.o lwe.o sampler.o pack.o fips202.o aes/aes.o aes/aes_c.o random.o


.PHONY: all clean 

all: test lib

lib: $(OBJS)
	rm -rf lwe
	mkdir lwe
	$(AR) lwe/liblwe.a $^
	$(RANLIB) lwe/liblwe.a
	
%.o:%.c
	$(CC) -c  $(CFLAGS) $< -o $@

test: tests/test_lwe.c lib
	$(CC) $(CFLAGS) -L./lwe tests/test_lwe.c -llwe -o lwe/test_lwe $(LDFLAGS)

clean:
	rm -rf *.o lwe
