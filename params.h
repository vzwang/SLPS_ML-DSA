#ifndef PARAMS_H
#define PARAMS_H

#include "config.h"

#define SEEDBYTES 32
#define CRHBYTES 64
#define TRBYTES 64
#define RNDBYTES 32
#define N 256
#define Q 8380417
#define D 13
#define ROOT_OF_UNITY 1753

#if DILITHIUM_MODE == 2
#define K 4
#define L 4
#define ETA 2
#define TAU 39
#define BETA 78
#define GAMMA1 (1 << 17)
#define GAMMA2 ((Q-1)/88)
#define OMEGA 80
#define CTILDEBYTES 32

#elif DILITHIUM_MODE == 3
#define K 6
#define L 5
#define ETA 4
#define TAU 49
#define BETA 196
#define GAMMA1 (1 << 19)
#define GAMMA2 ((Q-1)/32)
#define OMEGA 55
#define CTILDEBYTES 48

#elif DILITHIUM_MODE == 5
#define K 8
#define L 7
#define ETA 2
#define TAU 60
#define BETA 120
#define GAMMA1 (1 << 19)
#define GAMMA2 ((Q-1)/32)
#define OMEGA 75
#define CTILDEBYTES 64

#endif

#define POLYT1_PACKEDBYTES  320
#define SCLLS_POLYT_PACKEDBYTES   736
#define POLYT0_PACKEDBYTES  416
#define POLYVECH_PACKEDBYTES (OMEGA + K)

#if GAMMA1 == (1 << 17)
#define POLYZ_PACKEDBYTES   576
#elif GAMMA1 == (1 << 19)
#define POLYZ_PACKEDBYTES   640
#endif

#if GAMMA1 == (1 << 17)
#define SCLLS_POLYZ0_PACKEDBYTES   608
#elif GAMMA1 == (1 << 19)
#define SCLLS_POLYZ0_PACKEDBYTES   672
#endif

#if GAMMA2 == (Q-1)/88
#define POLYW1_PACKEDBYTES  192
#elif GAMMA2 == (Q-1)/32
#define POLYW1_PACKEDBYTES  128
#endif

#if ETA == 2
#define POLYETA_PACKEDBYTES  96
#elif ETA == 4
#define POLYETA_PACKEDBYTES 128
#endif

#define CRYPTO_PUBLICKEYBYTES (SEEDBYTES + K*POLYT1_PACKEDBYTES)
#define CRYPTO_SECRETKEYBYTES (2*SEEDBYTES \
                               + TRBYTES \
                               + L*POLYETA_PACKEDBYTES \
                               + K*POLYETA_PACKEDBYTES \
                               + K*POLYT0_PACKEDBYTES)
#define CRYPTO_BYTES (CTILDEBYTES + L*POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES)

#define SCLLS_PARAMSBYTES (SEEDBYTES + K*SCLLS_POLYT_PACKEDBYTES)
#define SCLLS_MSKBYTES (SEEDBYTES \
                        + TRBYTES \
                        + L*POLYETA_PACKEDBYTES \
                        + K*POLYETA_PACKEDBYTES)
#define SCLLS_CIDBYTES (CTILDEBYTES)
#define SCLLS_ZIDBYTES (L*POLYZ_PACKEDBYTES)
#define SCLLS_Z0BYTES (L*SCLLS_POLYZ0_PACKEDBYTES)
#define SCLLS_DIDBYTES (SCLLS_CIDBYTES + SCLLS_ZIDBYTES)
#define SCLLS_PIDBYTES (K*SCLLS_POLYT_PACKEDBYTES + K*POLYW1_PACKEDBYTES)
#define SCLLS_SIDBYTES (L*POLYETA_PACKEDBYTES + K*POLYETA_PACKEDBYTES \
                       + SCLLS_CIDBYTES + SCLLS_ZIDBYTES)
#define SCLLS_HWBYTES_PERPOLY (256*4/8)
#define SCLLS_HWBYTES (K*SCLLS_HWBYTES_PERPOLY)
#define SCLLS_SIGBYTES ( SCLLS_CIDBYTES + SCLLS_Z0BYTES + SCLLS_HWBYTES)
#endif
