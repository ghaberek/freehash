/*
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org/>
*/

#ifndef FREEHASH_H_
#define FREEHASH_H_
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <ctype.h>
#include <limits.h>

#ifndef FREEHASH_CUSTOM_H_
#define LFH_NOTHING
#define LFH_MD2
#define LFH_MD4
#define LFH_MD5
#define LFH_SHA1
#define LFH_SHA224
#define LFH_SHA256
#define LFH_SHA384
#define LFH_SHA512
#define LFH_SHA512_224
#define LFH_SHA512_256
#define LFH_SHA3
#define FREEHASH_CUSTOM_H_

#ifndef XMALLOC
#define XMALLOC  malloc
#endif
#ifndef XREALLOC
#define XREALLOC realloc
#endif
#ifndef XCALLOC
#define XCALLOC  calloc
#endif
#ifndef XFREE
#define XFREE    free
#endif

#ifndef XMEMSET
#define XMEMSET  memset
#endif
#ifndef XMEMCPY
#define XMEMCPY  memcpy
#endif
#ifndef XMEMMOVE
#define XMEMMOVE memmove
#endif
#ifndef XMEMCMP
#define XMEMCMP  memcmp
#endif
/* A memory compare function that has to run in constant time,
 * c.f. mem_neq() API summary.
 */
#ifndef XMEM_NEQ
#define XMEM_NEQ  mem_neq
#endif
#ifndef XSTRCMP
#define XSTRCMP  strcmp
#endif
#ifndef XSTRLEN
#define XSTRLEN  strlen
#endif
#ifndef XSTRNCPY
#define XSTRNCPY strncpy
#endif

#ifndef XCLOCK
#define XCLOCK   clock
#endif

#ifndef XQSORT
#define XQSORT qsort
#endif

#if ( defined(malloc) || defined(realloc) || defined(calloc) || defined(free) || \
		defined(memset) || defined(memcpy) || defined(memcmp) || defined(strcmp) || \
		defined(strlen) || defined(strncpy) || defined(clock) || defined(qsort) ) \
		&& !defined(LFH_NO_PROTOTYPES)
#define LFH_NO_PROTOTYPES
#endif

#if defined LFH_NOTHING && !defined LFH_EASY
	#define LFH_NO_CIPHERS
	#define LFH_NO_MODES
	#define LFH_NO_HASHES
	#define LFH_NO_MACS
	#define LFH_NO_PRNGS
	#define LFH_NO_PK
	#define LFH_NO_PKCS
	#define LFH_NO_MISC
#endif /* LFH_NOTHING */

#ifdef LFH_EASY
	#define LFH_NO_CIPHERS
	#define LFH_RIJNDAEL
	#define LFH_BLOWFISH
	#define LFH_DES
	#define LFH_CAST5

	#define LFH_NO_MODES
	#define LFH_ECB_MODE
	#define LFH_CBC_MODE
	#define LFH_CTR_MODE

	#define LFH_NO_HASHES
	#define LFH_SHA1
	#define LFH_SHA3
	#define LFH_SHA512
	#define LFH_SHA384
	#define LFH_SHA256
	#define LFH_SHA224
	#define LFH_HASH_HELPERS

	#define LFH_NO_MACS
	#define LFH_HMAC
	#define LFH_OMAC
	#define LFH_CCM_MODE

	#define LFH_NO_PRNGS
	#define LFH_SPRNG
	#define LFH_YARROW
	#define LFH_DEVRANDOM
	#define LFH_TRY_URANDOM_FIRST
	#define LFH_RNG_GET_BYTES
	#define LFH_RNG_MAKE_PRNG

	#define LFH_NO_PK
	#define LFH_MRSA
	#define LFH_MECC

	#define LFH_NO_MISC
	#define LFH_BASE64
#endif

#ifdef LFH_MINIMAL
	#define LFH_RIJNDAEL
	#define LFH_SHA256
	#define LFH_YARROW
	#define LFH_CTR_MODE

	#define LFH_RNG_MAKE_PRNG
	#define LFH_RNG_GET_BYTES
	#define LFH_DEVRANDOM
	#define LFH_TRY_URANDOM_FIRST

	#undef LFH_NO_FILE
#endif

#ifndef LFH_NO_TEST
	#define LFH_TEST
#endif

#ifdef LFH_YARROW

#ifdef ENCRYPT_ONLY
	#define LFH_YARROW_AES 0
#else
	#define LFH_YARROW_AES 2
#endif

#endif

#ifdef LFH_FORTUNA

#if !defined(LFH_FORTUNA_RESEED_RATELIMIT_STATIC) && \
		((defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L) || defined(_WIN32))

#define LFH_FORTUNA_RESEED_RATELIMIT_TIMED

#if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2, 17)
	#define LFH_CLOCK_GETTIME
#endif
#elif defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L
	#define LFH_CLOCK_GETTIME
#endif

#else

#ifndef LFH_FORTUNA_WD
#define LFH_FORTUNA_WD    10
#endif

#ifdef LFH_FORTUNA_RESEED_RATELIMIT_TIMED
/* make sure only one of
 *   LFH_FORTUNA_RESEED_RATELIMIT_STATIC
 * and
 *   LFH_FORTUNA_RESEED_RATELIMIT_TIMED
 * is defined.
 */
#undef LFH_FORTUNA_RESEED_RATELIMIT_TIMED
#warning "undef'ed LFH_FORTUNA_RESEED_RATELIMIT_TIMED, looks like your architecture doesn't support it"
#endif

#endif

#ifndef LFH_FORTUNA_POOLS
#define LFH_FORTUNA_POOLS 32
#endif

#endif /* LFH_FORTUNA */

#ifndef LFH_NO_PK

#define LFH_MRSA

#define LFH_MDH
#define LFH_DH768
#define LFH_DH1024
#define LFH_DH1536
#define LFH_DH2048

#if defined(LTM_DESC) || defined(GMP_DESC)
#define LFH_DH3072
#define LFH_DH4096
#define LFH_DH6144
#define LFH_DH8192
#endif

#define LFH_MDSA

#define LFH_CURVE25519

#define LFH_MECC

#define LFH_ECC_SHAMIR

#if defined(TFM_DESC) && defined(LFH_MECC)
	#define LFH_MECC_ACCEL
#endif

#endif /* LFH_NO_PK */

#if defined(LFH_MRSA) && !defined(LFH_NO_RSA_BLINDING)
#define LFH_RSA_BLINDING
#endif  /* LFH_NO_RSA_BLINDING */

#if defined(LFH_MRSA) && !defined(LFH_NO_RSA_CRT_HARDENING)
#define LFH_RSA_CRT_HARDENING
#endif  /* LFH_NO_RSA_CRT_HARDENING */

#if defined(LFH_MECC) && !defined(LFH_NO_ECC_TIMING_RESISTANT)
#define LFH_ECC_TIMING_RESISTANT
#endif

#ifdef LFH_MECC
#ifndef LFH_NO_CURVES
	#define LFH_ECC_BRAINPOOLP160R1
	#define LFH_ECC_BRAINPOOLP160T1
	#define LFH_ECC_BRAINPOOLP192R1
	#define LFH_ECC_BRAINPOOLP192T1
	#define LFH_ECC_BRAINPOOLP224R1
	#define LFH_ECC_BRAINPOOLP224T1
	#define LFH_ECC_BRAINPOOLP256R1
	#define LFH_ECC_BRAINPOOLP256T1
	#define LFH_ECC_BRAINPOOLP320R1
	#define LFH_ECC_BRAINPOOLP320T1
	#define LFH_ECC_BRAINPOOLP384R1
	#define LFH_ECC_BRAINPOOLP384T1
	#define LFH_ECC_BRAINPOOLP512R1
	#define LFH_ECC_BRAINPOOLP512T1
	#define LFH_ECC_PRIME192V2
	#define LFH_ECC_PRIME192V3
	#define LFH_ECC_PRIME239V1
	#define LFH_ECC_PRIME239V2
	#define LFH_ECC_PRIME239V3
	#define LFH_ECC_SECP112R1
	#define LFH_ECC_SECP112R2
	#define LFH_ECC_SECP128R1
	#define LFH_ECC_SECP128R2
	#define LFH_ECC_SECP160K1
	#define LFH_ECC_SECP160R1
	#define LFH_ECC_SECP160R2
	#define LFH_ECC_SECP192K1
	#define LFH_ECC_SECP192R1
	#define LFH_ECC_SECP224K1
	#define LFH_ECC_SECP224R1
	#define LFH_ECC_SECP256K1
	#define LFH_ECC_SECP256R1
	#define LFH_ECC_SECP384R1
	#define LFH_ECC_SECP521R1
#endif
#endif

#if defined(LFH_DER)
	#ifndef LFH_DER_MAX_RECURSION
		#define LFH_DER_MAX_RECURSION 30
	#endif
#endif

#if defined(LFH_MECC) || defined(LFH_MRSA) || defined(LFH_MDSA) || defined(LFH_SSH)
	#define LFH_MPI

	#ifndef LFH_PK_MAX_RETRIES
		#define LFH_PK_MAX_RETRIES  20
	#endif
#endif

#ifdef LFH_MRSA
	#define LFH_PKCS_1
#endif

#if defined(LFH_MRSA) || defined(LFH_MECC)
	#define LFH_PKCS_8
#endif

#ifdef LFH_PKCS_8
	#define LFH_PADDING
	#define LFH_PBES
#endif

#if defined(LFH_CLEAN_STACK)
	#error LFH_CLEAN_STACK is considered as broken
#endif

#if defined(LFH_PBES) && !defined(LFH_PKCS_5)
	#error LFH_PBES requires LFH_PKCS_5
#endif

#if defined(LFH_PBES) && !defined(LFH_PKCS_12)
	#error LFH_PBES requires LFH_PKCS_12
#endif

#if defined(LFH_PKCS_5) && !defined(LFH_HMAC)
	#error LFH_PKCS_5 requires LFH_HMAC
#endif

#if defined(LFH_PKCS_5) && !defined(LFH_HASH_HELPERS)
	#error LFH_PKCS_5 requires LFH_HASH_HELPERS
#endif

#if defined(LFH_PELICAN) && !defined(LFH_RIJNDAEL)
	#error Pelican-MAC requires LFH_RIJNDAEL
#endif

#if defined(LFH_EAX_MODE) && !(defined(LFH_CTR_MODE) && defined(LFH_OMAC))
	#error LFH_EAX_MODE requires CTR and LFH_OMAC mode
#endif

#if defined(LFH_YARROW) && !defined(LFH_CTR_MODE)
	#error LFH_YARROW requires LFH_CTR_MODE chaining mode to be defined!
#endif

#if defined(LFH_DER) && !defined(LFH_MPI)
	#error ASN.1 DER requires MPI functionality
#endif

#if (defined(LFH_MDSA) || defined(LFH_MRSA) || defined(LFH_MECC)) && !defined(LFH_DER)
	#error PK requires ASN.1 DER functionality, make sure LFH_DER is enabled
#endif

#if defined(LFH_BCRYPT) && !defined(LFH_BLOWFISH)
	#error LFH_BCRYPT requires LFH_BLOWFISH
#endif

#if defined(LFH_CHACHA20POLY1305_MODE) && (!defined(LFH_CHACHA) || !defined(LFH_POLY1305))
	#error LFH_CHACHA20POLY1305_MODE requires LFH_CHACHA + LFH_POLY1305
#endif

#if defined(LFH_CHACHA20_PRNG) && !defined(LFH_CHACHA)
	#error LFH_CHACHA20_PRNG requires LFH_CHACHA
#endif

#if defined(LFH_XSALSA20) && !defined(LFH_SALSA20)
	#error LFH_XSALSA20 requires LFH_SALSA20
#endif

#if defined(LFH_RC4) && !defined(LFH_RC4_STREAM)
	#error LFH_RC4 requires LFH_RC4_STREAM
#endif

#if defined(LFH_SOBER128) && !defined(LFH_SOBER128_STREAM)
	#error LFH_SOBER128 requires LFH_SOBER128_STREAM
#endif

#if defined(LFH_BLAKE2SMAC) && !defined(LFH_BLAKE2S)
	#error LFH_BLAKE2SMAC requires LFH_BLAKE2S
#endif

#if defined(LFH_BLAKE2BMAC) && !defined(LFH_BLAKE2B)
	#error LFH_BLAKE2BMAC requires LFH_BLAKE2B
#endif

#if defined(LFH_SPRNG) && !defined(LFH_RNG_GET_BYTES)
	#error LFH_SPRNG requires LFH_RNG_GET_BYTES
#endif

#if defined(LFH_NO_MATH) && (defined(LTM_DESC) || defined(TFM_DESC) || defined(GMP_DESC))
	#error LFH_NO_MATH defined, but also a math descriptor
#endif

#ifdef LFH_PTHREAD

#include <pthread.h>

#define LFH_MUTEX_GLOBAL(x)   pthread_mutex_t x = PTHREAD_MUTEX_INITIALIZER;
#define LFH_MUTEX_PROTO(x)    extern pthread_mutex_t x;
#define LFH_MUTEX_TYPE(x)     pthread_mutex_t x;
#define LFH_MUTEX_INIT(x)     LFH_ARGCHK(pthread_mutex_init(x, NULL) == 0);
#define LFH_MUTEX_LOCK(x)     LFH_ARGCHK(pthread_mutex_lock(x) == 0);
#define LFH_MUTEX_UNLOCK(x)   LFH_ARGCHK(pthread_mutex_unlock(x) == 0);
#define LFH_MUTEX_DESTROY(x)  LFH_ARGCHK(pthread_mutex_destroy(x) == 0);

#else

#define LFH_MUTEX_GLOBAL(x)
#define LFH_MUTEX_PROTO(x)
#define LFH_MUTEX_TYPE(x)
#define LFH_MUTEX_INIT(x)
#define LFH_MUTEX_LOCK(x)
#define LFH_MUTEX_UNLOCK(x)
#define LFH_MUTEX_DESTROY(x)

#endif

#endif

#ifndef LFH_NO_FILE
	#ifndef LFH_FILE_READ_BUFSIZE
	#define LFH_FILE_READ_BUFSIZE 8192
	#endif
#endif

#if !defined(LFH_ECC_SECP112R1) && defined(LFH_ECC112)
#define LFH_ECC_SECP112R1
#undef LFH_ECC112
#endif
#if !defined(LFH_ECC_SECP128R1) && defined(LFH_ECC128)
#define LFH_ECC_SECP128R1
#undef LFH_ECC128
#endif
#if !defined(LFH_ECC_SECP160R1) && defined(LFH_ECC160)
#define LFH_ECC_SECP160R1
#undef LFH_ECC160
#endif
#if !defined(LFH_ECC_SECP192R1) && defined(LFH_ECC192)
#define LFH_ECC_SECP192R1
#undef LFH_ECC192
#endif
#if !defined(LFH_ECC_SECP224R1) && defined(LFH_ECC224)
#define LFH_ECC_SECP224R1
#undef LFH_ECC224
#endif
#if !defined(LFH_ECC_SECP256R1) && defined(LFH_ECC256)
#define LFH_ECC_SECP256R1
#undef LFH_ECC256
#endif
#if !defined(LFH_ECC_SECP384R1) && defined(LFH_ECC384)
#define LFH_ECC_SECP384R1
#undef LFH_ECC384
#endif
#if !defined(LFH_ECC_SECP512R1) && defined(LFH_ECC521)
#define LFH_ECC_SECP521R1
#undef LFH_ECC521
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define CRYPT   0x0118
#define SCRYPT  "1.18.2-develop"

#define MAXBLOCKSIZE  144

#ifndef TAB_SIZE
#define TAB_SIZE      34
#endif

enum {
	CRYPT_OK=0,             /* Result OK */
	CRYPT_ERROR,            /* Generic Error */
	CRYPT_NOP,              /* Not a failure but no operation was performed */

	CRYPT_INVALID_KEYSIZE,  /* Invalid key size given */
	CRYPT_INVALID_ROUNDS,   /* Invalid number of rounds */
	CRYPT_FAIL_TESTVECTOR,  /* Algorithm failed test vectors */

	CRYPT_BUFFER_OVERFLOW,  /* Not enough space for output */
	CRYPT_INVALID_PACKET,   /* Invalid input packet given */

	CRYPT_INVALID_PRNGSIZE, /* Invalid number of bits for a PRNG */
	CRYPT_ERROR_READPRNG,   /* Could not read enough from PRNG */

	CRYPT_INVALID_CIPHER,   /* Invalid cipher specified */
	CRYPT_INVALID_HASH,     /* Invalid hash specified */
	CRYPT_INVALID_PRNG,     /* Invalid PRNG specified */

	CRYPT_MEM,              /* Out of memory */

	CRYPT_PK_TYPE_MISMATCH, /* Not equivalent types of PK keys */
	CRYPT_PK_NOT_PRIVATE,   /* Requires a private PK key */

	CRYPT_INVALID_ARG,      /* Generic invalid argument */
	CRYPT_FILE_NOTFOUND,    /* File Not Found */

	CRYPT_PK_INVALID_TYPE,  /* Invalid type of PK key */

	CRYPT_OVERFLOW,         /* An overflow of a value was detected/prevented */

	CRYPT_PK_ASN1_ERROR,    /* An error occurred while en- or decoding ASN.1 data */

	CRYPT_INPUT_TOO_LONG,   /* The input was longer than expected. */

	CRYPT_PK_INVALID_SIZE,  /* Invalid size input for PK parameters */

	CRYPT_INVALID_PRIME_SIZE,/* Invalid size of prime requested */
	CRYPT_PK_INVALID_PADDING, /* Invalid padding on input */

	CRYPT_HASH_OVERFLOW      /* Hash applied to too many bits */
};

/* This is the build config file.
 *
 * With this you can setup what to inlcude/exclude automatically during any build.  Just comment
 * out the line that #define's the word for the thing you want to remove.  phew!
 */

#ifndef FREEHASH_CFG_H
#define FREEHASH_CFG_H

#if defined(_WIN32) || defined(_MSC_VER)
	#define LFH_CALL __cdecl
#elif !defined(LFH_CALL)
	#define LFH_CALL
#endif

#ifndef LFH_EXPORT
	#define LFH_EXPORT
#endif

#ifndef LFH_NO_PROTOTYPES

LFH_EXPORT void * LFH_CALL XMALLOC(size_t n);
LFH_EXPORT void * LFH_CALL XREALLOC(void *p, size_t n);
LFH_EXPORT void * LFH_CALL XCALLOC(size_t n, size_t s);
LFH_EXPORT void LFH_CALL XFREE(void *p);

LFH_EXPORT void LFH_CALL XQSORT(void *base, size_t nmemb, size_t size, int(*compar)(const void *, const void *));

LFH_EXPORT clock_t LFH_CALL XCLOCK(void);

LFH_EXPORT void * LFH_CALL XMEMCPY(void *dest, const void *src, size_t n);
LFH_EXPORT int   LFH_CALL XMEMCMP(const void *s1, const void *s2, size_t n);
LFH_EXPORT void * LFH_CALL XMEMSET(void *s, int c, size_t n);

LFH_EXPORT int   LFH_CALL XSTRCMP(const char *s1, const char *s2);

#endif

#if defined(__GNUC__) || defined(__xlc__)
	#define LFH_INLINE __inline__
#elif defined(_MSC_VER) || defined(__HP_cc)
	#define LFH_INLINE __inline
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
	#define LFH_INLINE inline
#else
	#define LFH_INLINE
#endif

#if defined(__clang__) || defined(__GNUC_MINOR__)
#define LFH_NORETURN __attribute__ ((noreturn))
#elif defined(_MSC_VER)
#define LFH_NORETURN __declspec(noreturn)
#else
#define LFH_NORETURN
#endif

#ifndef ARGTYPE
	#define ARGTYPE  0
#endif

#undef LFH_ENCRYPT
#define LFH_ENCRYPT 0
#undef LFH_DECRYPT
#define LFH_DECRYPT 1

/* Controls endianess and size of registers.  Leave uncommented to get platform neutral [slower] code
 *
 * Note: in order to use the optimized macros your platform must support unaligned 32 and 64 bit read/writes.
 * The x86 platforms allow this but some others [ARM for instance] do not.  On those platforms you **MUST**
 * use the portable [slower] macros.
 */
#if defined(__i386__) || defined(__i386) || defined(_M_IX86)
	#define ENDIAN_LITTLE
	#define ENDIAN_32BITWORD
	#define LFH_FAST
#endif

#if defined(__x86_64__) || defined(_M_X64) || defined(_M_AMD64)
	#define ENDIAN_LITTLE
	#define ENDIAN_64BITWORD
	#define LFH_FAST
#endif

#if defined(LFH_PPC32)
	#define ENDIAN_BIG
	#define ENDIAN_32BITWORD
	#define LFH_FAST
#endif

#if (defined(__R5900) || defined(R5900) || defined(__R5900__)) && (defined(_mips) || defined(__mips__) || defined(mips))
	#define ENDIAN_64BITWORD
	#if defined(_MIPSEB) || defined(__MIPSEB) || defined(__MIPSEB__)
	 #define ENDIAN_BIG
	#else
	 #define ENDIAN_LITTLE
	#endif
#endif

#if defined(_AIX) && defined(_BIG_ENDIAN)
	#define ENDIAN_BIG
	#if defined(__LP64__) || defined(_ARCH_PPC64)
	#define ENDIAN_64BITWORD
	#else
	#define ENDIAN_32BITWORD
	#endif
#endif

#if defined(__hpux) || defined(__hpux__)
	#define ENDIAN_BIG
	#if defined(__ia64) || defined(__ia64__) || defined(__LP64__)
	#define ENDIAN_64BITWORD
	#else
	#define ENDIAN_32BITWORD
	#endif
#endif

#if defined(__APPLE__) && defined(__MACH__)
	#if defined(__LITTLE_ENDIAN__) || defined(__x86_64__)
	#define ENDIAN_LITTLE
	#else
	#define ENDIAN_BIG
	#endif
	#if defined(__LP64__) || defined(__x86_64__)
	#define ENDIAN_64BITWORD
	#else
	#define ENDIAN_32BITWORD
	#endif
#endif

#if defined(__sparc__) || defined(__sparc)
	#define ENDIAN_BIG
	#if defined(__arch64__) || defined(__sparcv9) || defined(__sparc_v9__)
	#define ENDIAN_64BITWORD
	#else
	#define ENDIAN_32BITWORD
	#endif
#endif

#if defined(__s390x__) || defined(__s390__)
	#define ENDIAN_BIG
	#if defined(__s390x__)
	#define ENDIAN_64BITWORD
	#else
	#define ENDIAN_32BITWORD
	#endif
#endif

#if defined(__powerpc64__) || defined(__ppc64__) || defined(__PPC64__)
	#define ENDIAN_64BITWORD
	#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
		#define ENDIAN_BIG
	#elif  __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		#define ENDIAN_LITTLE
	#endif
	#define LFH_FAST
#endif

#if !defined(ENDIAN_BIG) && !defined(ENDIAN_LITTLE)
	#if defined(_BYTE_ORDER) && _BYTE_ORDER == _BIG_ENDIAN || \
		defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN || \
		defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ || \
		defined(__BIG_ENDIAN__) || \
		defined(__ARMEB__) || defined(__THUMBEB__) || defined(__AARCH64EB__) || \
		defined(_MIPSEB) || defined(__MIPSEB) || defined(__MIPSEB__) || \
		defined(__m68k__)
	#define ENDIAN_BIG
	#elif defined(_BYTE_ORDER) && _BYTE_ORDER == _LITTLE_ENDIAN || \
		defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN || \
		defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ || \
		defined(__LITTLE_ENDIAN__) || \
		defined(__ARMEL__) || defined(__THUMBEL__) || defined(__AARCH64EL__) || \
		defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__)
	#define ENDIAN_LITTLE
	#else
	#error Cannot detect endianness
	#endif
#endif

#ifdef _MSC_VER
	#define CONST64(n) n ## ui64
	typedef unsigned __int64 ulong64;
	typedef __int64 long64;
#else
	#define CONST64(n) n ## ULL
	typedef unsigned long long ulong64;
	typedef long long long64;
#endif

#if defined(__x86_64__) || defined(_M_X64) || defined(_M_AMD64) || \
	defined(__powerpc64__) || defined(__ppc64__) || defined(__PPC64__) || \
	defined(__s390x__) || defined(__arch64__) || defined(__aarch64__) || \
	defined(__sparcv9) || defined(__sparc_v9__) || defined(__sparc64__) || \
	defined(__ia64) || defined(__ia64__) || defined(__itanium__) || defined(_M_IA64) || \
	defined(__LP64__) || defined(_LP64) || defined(__64BIT__)
	typedef unsigned ulong32;
	#if !defined(ENDIAN_64BITWORD) && !defined(ENDIAN_32BITWORD)
	 #define ENDIAN_64BITWORD
	#endif
#else
	typedef unsigned long ulong32;
	#if !defined(ENDIAN_64BITWORD) && !defined(ENDIAN_32BITWORD)
	 #define ENDIAN_32BITWORD
	#endif
#endif

#if defined(ENDIAN_64BITWORD) && !defined(_MSC_VER)
typedef unsigned long long lfh_mp_digit;
#else
typedef unsigned long lfh_mp_digit;
#endif

#ifdef LFH_NO_ASM
	#define ENDIAN_NEUTRAL
	#undef ENDIAN_32BITWORD
	#undef ENDIAN_64BITWORD
	#undef LFH_FAST
	#define LFH_NO_BSWAP
	#define LFH_NO_ROLC
	#define LFH_NO_ROTATE
#endif

#if defined(LFH_NO_FAST) || (__GNUC__ < 4) || defined(__STRICT_ANSI__)
	#undef LFH_FAST
#endif

#ifdef LFH_FAST
	#define LFH_FAST_TYPE_PTR_CAST(x) ((LFH_FAST_TYPE*)(void*)(x))
	#ifdef ENDIAN_64BITWORD
	typedef ulong64 __attribute__((__may_alias__)) LFH_FAST_TYPE;
	#else
	typedef ulong32 __attribute__((__may_alias__)) LFH_FAST_TYPE;
	#endif
#endif

#if !defined(ENDIAN_NEUTRAL) && (defined(ENDIAN_BIG) || defined(ENDIAN_LITTLE)) && !(defined(ENDIAN_32BITWORD) || defined(ENDIAN_64BITWORD))
	#error You must specify a word size as well as endianess in tomcrypt_cfg.h
#endif

#if !(defined(ENDIAN_BIG) || defined(ENDIAN_LITTLE))
	#define ENDIAN_NEUTRAL
#endif

#if (defined(ENDIAN_32BITWORD) && defined(ENDIAN_64BITWORD))
	#error Cannot be 32 and 64 bit words...
#endif

/* gcc 4.3 and up has a bswap builtin; detect it by gcc version.
 * clang also supports the bswap builtin, and although clang pretends
 * to be gcc (macro-wise, anyway), clang pretends to be a version
 * prior to gcc 4.3, so we can't detect bswap that way.  Instead,
 * clang has a __has_builtin mechanism that can be used to check
 * for builtins:
 * http://clang.llvm.org/docs/LanguageExtensions.html#feature_check */
#ifndef __has_builtin
	#define __has_builtin(x) 0
#endif
#if !defined(LFH_NO_BSWAP) && defined(__GNUC__) && \
	((__GNUC__ * 100 + __GNUC_MINOR__ >= 403) || \
	(__has_builtin(__builtin_bswap32) && __has_builtin(__builtin_bswap64)))
	#define LFH_HAVE_BSWAP_BUILTIN
#endif

#if !defined(LFH_NO_ROTATE) && (__has_builtin(__builtin_rotateleft32) && __has_builtin(__builtin_rotateright32))
	#define LFH_HAVE_ROTATE_BUILTIN
#endif

#if defined(__GNUC__)
	#define LFH_ALIGN(n) __attribute__((aligned(n)))
#else
	#define LFH_ALIGN(n)
#endif

#if defined(__GNUC__) && (__GNUC__ * 100 + __GNUC_MINOR__ >= 405)
#  define LFH_DEPRECATED(s) __attribute__((deprecated("replaced by " #s)))
#  define PRIVATE_LFH_DEPRECATED_PRAGMA(s) _Pragma(#s)
#  define LFH_DEPRECATED_PRAGMA(s) PRIVATE_LFH_DEPRECATED_PRAGMA(GCC warning s)
#elif defined(__GNUC__) && (__GNUC__ * 100 + __GNUC_MINOR__ >= 301)
#  define LFH_DEPRECATED(s) __attribute__((deprecated))
#  define LFH_DEPRECATED_PRAGMA(s)
#elif defined(_MSC_VER) && _MSC_VER >= 1500
#  define LFH_DEPRECATED(s) __declspec(deprecated("replaced by " #s))
#  define LFH_DEPRECATED_PRAGMA(s) __pragma(message(s))
#else
#  define LFH_DEPRECATED(s)
#  define LFH_DEPRECATED_PRAGMA(s)
#endif

#endif /* FREEHASH_CFG_H */

#if defined(LFH_SHA3) || defined(LFH_KECCAK)
struct sha3_state {
	ulong64 saved;                  /* the portion of the input message that we didn't consume yet */
	ulong64 s[25];
	unsigned char sb[25 * 8];       /* used for storing `ulong64 s[25]` as little-endian bytes */
	unsigned short byte_index;      /* 0..7--the next byte after the set one (starts from 0; 0--none are buffered) */
	unsigned short word_index;      /* 0..24--the next word to integrate input (starts from 0) */
	unsigned short capacity_words;  /* the double size of the hash output in words (e.g. 16 for Keccak 512) */
	unsigned short xof_flag;
};
#endif

#ifdef LFH_SHA512
struct sha512_state {
	ulong64  length, state[8];
	unsigned long curlen;
	unsigned char buf[128];
};
#endif

#ifdef LFH_SHA256
struct sha256_state {
	ulong64 length;
	ulong32 state[8], curlen;
	unsigned char buf[64];
};
#endif

#ifdef LFH_SHA1
struct sha1_state {
	ulong64 length;
	ulong32 state[5], curlen;
	unsigned char buf[64];
};
#endif

#ifdef LFH_MD5
struct md5_state {
	ulong64 length;
	ulong32 state[4], curlen;
	unsigned char buf[64];
};
#endif

#ifdef LFH_MD4
struct md4_state {
	ulong64 length;
	ulong32 state[4], curlen;
	unsigned char buf[64];
};
#endif

#ifdef LFH_TIGER
struct tiger_state {
	ulong64 state[3], length;
	unsigned long curlen;
	unsigned char buf[64];
};
#endif

#ifdef LFH_MD2
struct md2_state {
	unsigned char chksum[16], X[48], buf[16];
	unsigned long curlen;
};
#endif

#ifdef LFH_RIPEMD128
struct rmd128_state {
	ulong64 length;
	unsigned char buf[64];
	ulong32 curlen, state[4];
};
#endif

#ifdef LFH_RIPEMD160
struct rmd160_state {
	ulong64 length;
	unsigned char buf[64];
	ulong32 curlen, state[5];
};
#endif

#ifdef LFH_RIPEMD256
struct rmd256_state {
	ulong64 length;
	unsigned char buf[64];
	ulong32 curlen, state[8];
};
#endif

#ifdef LFH_RIPEMD320
struct rmd320_state {
	ulong64 length;
	unsigned char buf[64];
	ulong32 curlen, state[10];
};
#endif

#ifdef LFH_WHIRLPOOL
struct whirlpool_state {
	ulong64 length, state[8];
	unsigned char buf[64];
	ulong32 curlen;
};
#endif

#ifdef LFH_CHC_HASH
struct chc_state {
	ulong64 length;
	unsigned char state[MAXBLOCKSIZE], buf[MAXBLOCKSIZE];
	ulong32 curlen;
};
#endif

#ifdef LFH_BLAKE2S
struct blake2s_state {
	ulong32 h[8];
	ulong32 t[2];
	ulong32 f[2];
	unsigned char buf[64];
	unsigned long curlen;
	unsigned long outlen;
	unsigned char last_node;
};
#endif

#ifdef LFH_BLAKE2B
struct blake2b_state {
	ulong64 h[8];
	ulong64 t[2];
	ulong64 f[2];
	unsigned char buf[128];
	unsigned long curlen;
	unsigned long outlen;
	unsigned char last_node;
};
#endif

typedef union Hash_state {
	char dummy[1];
#ifdef LFH_CHC_HASH
	struct chc_state chc;
#endif
#ifdef LFH_WHIRLPOOL
	struct whirlpool_state whirlpool;
#endif
#if defined(LFH_SHA3) || defined(LFH_KECCAK)
	struct sha3_state sha3;
#endif
#ifdef LFH_SHA512
	struct sha512_state sha512;
#endif
#ifdef LFH_SHA256
	struct sha256_state sha256;
#endif
#ifdef LFH_SHA1
	struct sha1_state   sha1;
#endif
#ifdef LFH_MD5
	struct md5_state    md5;
#endif
#ifdef LFH_MD4
	struct md4_state    md4;
#endif
#ifdef LFH_MD2
	struct md2_state    md2;
#endif
#ifdef LFH_TIGER
	struct tiger_state  tiger;
#endif
#ifdef LFH_RIPEMD128
	struct rmd128_state rmd128;
#endif
#ifdef LFH_RIPEMD160
	struct rmd160_state rmd160;
#endif
#ifdef LFH_RIPEMD256
	struct rmd256_state rmd256;
#endif
#ifdef LFH_RIPEMD320
	struct rmd320_state rmd320;
#endif
#ifdef LFH_BLAKE2S
	struct blake2s_state blake2s;
#endif
#ifdef LFH_BLAKE2B
	struct blake2b_state blake2b;
#endif

	void *data;
} hash_state;

/** hash descriptor */
extern  struct lfh_hash_descriptor {
	/** name of hash */
	const char *name;
	/** internal ID */
	unsigned char ID;
	/** Size of digest in octets */
	unsigned long hashsize;
	/** Input block size in octets */
	unsigned long blocksize;
	/** ASN.1 OID */
	unsigned long OID[16];
	/** Length of DER encoding */
	unsigned long OIDlen;

	/** Init a hash state
		@param hash   The hash to initialize
		@return CRYPT_OK if successful
	*/
	int (*init)(hash_state *hash);
	/** Process a block of data
		@param hash   The hash state
		@param in     The data to hash
		@param inlen  The length of the data (octets)
		@return CRYPT_OK if successful
	*/
	int (*process)(hash_state *hash, const unsigned char *in, unsigned long inlen);
	/** Produce the digest and store it
		@param hash   The hash state
		@param out    [out] The destination of the digest
		@return CRYPT_OK if successful
	*/
	int (*done)(hash_state *hash, unsigned char *out);
	/** Self-test
		@return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
	*/
	int (*test)(void);

	int  (*hmac_block)(const unsigned char *key, unsigned long  keylen,
						const unsigned char *in,  unsigned long  inlen,
							 unsigned char *out, unsigned long *outlen);

} hash_descriptor[];

#ifdef LFH_CHC_HASH
int chc_register(int cipher);
int chc_init(hash_state * md);
int chc_process(hash_state * md, const unsigned char *in, unsigned long inlen);
int chc_done(hash_state * md, unsigned char *out);
int chc_test(void);
extern const struct lfh_hash_descriptor chc_desc;
#endif

#ifdef LFH_WHIRLPOOL
int whirlpool_init(hash_state * md);
int whirlpool_process(hash_state * md, const unsigned char *in, unsigned long inlen);
int whirlpool_done(hash_state * md, unsigned char *out);
int whirlpool_test(void);
extern const struct lfh_hash_descriptor whirlpool_desc;
#endif

#if defined(LFH_SHA3) || defined(LFH_KECCAK)
int sha3_512_init(hash_state * md);
int sha3_384_init(hash_state * md);
int sha3_256_init(hash_state * md);
int sha3_224_init(hash_state * md);
int sha3_process(hash_state * md, const unsigned char *in, unsigned long inlen);
#endif

#ifdef LFH_SHA3
int sha3_512_test(void);
extern const struct lfh_hash_descriptor sha3_512_desc;
int sha3_384_test(void);
extern const struct lfh_hash_descriptor sha3_384_desc;
int sha3_256_test(void);
extern const struct lfh_hash_descriptor sha3_256_desc;
int sha3_224_test(void);
extern const struct lfh_hash_descriptor sha3_224_desc;
int sha3_done(hash_state *md, unsigned char *out);
int sha3_shake_init(hash_state *md, int num);
#define sha3_shake_process(a,b,c) sha3_process(a,b,c)
int sha3_shake_done(hash_state *md, unsigned char *out, unsigned long outlen);
int sha3_shake_test(void);
int sha3_shake_memory(int num, const unsigned char *in, unsigned long inlen, unsigned char *out, const unsigned long *outlen);
#endif

#ifdef LFH_KECCAK
#define keccak_512_init(a)    sha3_512_init(a)
#define keccak_384_init(a)    sha3_384_init(a)
#define keccak_256_init(a)    sha3_256_init(a)
#define keccak_224_init(a)    sha3_224_init(a)
#define keccak_process(a,b,c) sha3_process(a,b,c)
extern const struct lfh_hash_descriptor keccak_512_desc;
int keccak_512_test(void);
extern const struct lfh_hash_descriptor keccak_384_desc;
int keccak_384_test(void);
extern const struct lfh_hash_descriptor keccak_256_desc;
int keccak_256_test(void);
extern const struct lfh_hash_descriptor keccak_224_desc;
int keccak_224_test(void);
int keccak_done(hash_state *md, unsigned char *out);
#endif

#ifdef LFH_SHA512
int sha512_init(hash_state * md);
int sha512_process(hash_state * md, const unsigned char *in, unsigned long inlen);
int sha512_done(hash_state * md, unsigned char *out);
int sha512_test(void);
extern const struct lfh_hash_descriptor sha512_desc;
#endif

#ifdef LFH_SHA384
#ifndef LFH_SHA512
	#error LFH_SHA512 is required for LFH_SHA384
#endif
int sha384_init(hash_state * md);
#define sha384_process sha512_process
int sha384_done(hash_state * md, unsigned char *out);
int sha384_test(void);
extern const struct lfh_hash_descriptor sha384_desc;
#endif

#ifdef LFH_SHA512_256
#ifndef LFH_SHA512
	#error LFH_SHA512 is required for LFH_SHA512_256
#endif
int sha512_256_init(hash_state * md);
#define sha512_256_process sha512_process
int sha512_256_done(hash_state * md, unsigned char *out);
int sha512_256_test(void);
extern const struct lfh_hash_descriptor sha512_256_desc;
#endif

#ifdef LFH_SHA512_224
#ifndef LFH_SHA512
	#error LFH_SHA512 is required for LFH_SHA512_224
#endif
int sha512_224_init(hash_state * md);
#define sha512_224_process sha512_process
int sha512_224_done(hash_state * md, unsigned char *out);
int sha512_224_test(void);
extern const struct lfh_hash_descriptor sha512_224_desc;
#endif

#ifdef LFH_SHA256
int sha256_init(hash_state * md);
int sha256_process(hash_state * md, const unsigned char *in, unsigned long inlen);
int sha256_done(hash_state * md, unsigned char *out);
int sha256_test(void);
extern const struct lfh_hash_descriptor sha256_desc;

#ifdef LFH_SHA224
#ifndef LFH_SHA256
	#error LFH_SHA256 is required for LFH_SHA224
#endif
int sha224_init(hash_state * md);
#define sha224_process sha256_process
int sha224_done(hash_state * md, unsigned char *out);
int sha224_test(void);
extern const struct lfh_hash_descriptor sha224_desc;
#endif
#endif

#ifdef LFH_SHA1
int sha1_init(hash_state * md);
int sha1_process(hash_state * md, const unsigned char *in, unsigned long inlen);
int sha1_done(hash_state * md, unsigned char *out);
int sha1_test(void);
extern const struct lfh_hash_descriptor sha1_desc;
#endif

#ifdef LFH_BLAKE2S
extern const struct lfh_hash_descriptor blake2s_256_desc;
int blake2s_256_init(hash_state * md);
int blake2s_256_test(void);

extern const struct lfh_hash_descriptor blake2s_224_desc;
int blake2s_224_init(hash_state * md);
int blake2s_224_test(void);

extern const struct lfh_hash_descriptor blake2s_160_desc;
int blake2s_160_init(hash_state * md);
int blake2s_160_test(void);

extern const struct lfh_hash_descriptor blake2s_128_desc;
int blake2s_128_init(hash_state * md);
int blake2s_128_test(void);

int blake2s_init(hash_state * md, unsigned long outlen, const unsigned char *key, unsigned long keylen);
int blake2s_process(hash_state * md, const unsigned char *in, unsigned long inlen);
int blake2s_done(hash_state * md, unsigned char *out);
#endif

#ifdef LFH_BLAKE2B
extern const struct lfh_hash_descriptor blake2b_512_desc;
int blake2b_512_init(hash_state * md);
int blake2b_512_test(void);

extern const struct lfh_hash_descriptor blake2b_384_desc;
int blake2b_384_init(hash_state * md);
int blake2b_384_test(void);

extern const struct lfh_hash_descriptor blake2b_256_desc;
int blake2b_256_init(hash_state * md);
int blake2b_256_test(void);

extern const struct lfh_hash_descriptor blake2b_160_desc;
int blake2b_160_init(hash_state * md);
int blake2b_160_test(void);

int blake2b_init(hash_state * md, unsigned long outlen, const unsigned char *key, unsigned long keylen);
int blake2b_process(hash_state * md, const unsigned char *in, unsigned long inlen);
int blake2b_done(hash_state * md, unsigned char *out);
#endif

#ifdef LFH_MD5
int md5_init(hash_state * md);
int md5_process(hash_state * md, const unsigned char *in, unsigned long inlen);
int md5_done(hash_state * md, unsigned char *out);
int md5_test(void);
extern const struct lfh_hash_descriptor md5_desc;
#endif

#ifdef LFH_MD4
int md4_init(hash_state * md);
int md4_process(hash_state * md, const unsigned char *in, unsigned long inlen);
int md4_done(hash_state * md, unsigned char *out);
int md4_test(void);
extern const struct lfh_hash_descriptor md4_desc;
#endif

#ifdef LFH_MD2
int md2_init(hash_state * md);
int md2_process(hash_state * md, const unsigned char *in, unsigned long inlen);
int md2_done(hash_state * md, unsigned char *out);
int md2_test(void);
extern const struct lfh_hash_descriptor md2_desc;
#endif

#ifdef LFH_TIGER
int tiger_init(hash_state * md);
int tiger_process(hash_state * md, const unsigned char *in, unsigned long inlen);
int tiger_done(hash_state * md, unsigned char *out);
int tiger_test(void);
extern const struct lfh_hash_descriptor tiger_desc;
#endif

#ifdef LFH_RIPEMD128
int rmd128_init(hash_state * md);
int rmd128_process(hash_state * md, const unsigned char *in, unsigned long inlen);
int rmd128_done(hash_state * md, unsigned char *out);
int rmd128_test(void);
extern const struct lfh_hash_descriptor rmd128_desc;
#endif

#ifdef LFH_RIPEMD160
int rmd160_init(hash_state * md);
int rmd160_process(hash_state * md, const unsigned char *in, unsigned long inlen);
int rmd160_done(hash_state * md, unsigned char *out);
int rmd160_test(void);
extern const struct lfh_hash_descriptor rmd160_desc;
#endif

#ifdef LFH_RIPEMD256
int rmd256_init(hash_state * md);
int rmd256_process(hash_state * md, const unsigned char *in, unsigned long inlen);
int rmd256_done(hash_state * md, unsigned char *out);
int rmd256_test(void);
extern const struct lfh_hash_descriptor rmd256_desc;
#endif

#ifdef LFH_RIPEMD320
int rmd320_init(hash_state * md);
int rmd320_process(hash_state * md, const unsigned char *in, unsigned long inlen);
int rmd320_done(hash_state * md, unsigned char *out);
int rmd320_test(void);
extern const struct lfh_hash_descriptor rmd320_desc;
#endif

int find_hash(const char *name);
int find_hash_id(unsigned char ID);
int find_hash_oid(const unsigned long *ID, unsigned long IDlen);
int find_hash_any(const char *name, int digestlen);
int register_hash(const struct lfh_hash_descriptor *hash);
int unregister_hash(const struct lfh_hash_descriptor *hash);
int register_all_hashes(void);
int hash_is_valid(int idx);

LFH_MUTEX_PROTO(lfh_hash_mutex)

int hash_memory(int hash,
				const unsigned char *in,  unsigned long inlen,
						unsigned char *out, unsigned long *outlen);
int hash_memory_multi(int hash, unsigned char *out, unsigned long *outlen,
						const unsigned char *in, unsigned long inlen, ...);

#ifndef LFH_NO_FILE
int hash_filehandle(int hash, FILE *in, unsigned char *out, unsigned long *outlen);
int hash_file(int hash, const char *fname, unsigned char *out, unsigned long *outlen);
#endif

#ifdef LFH_BASE64
int base64_encode(const unsigned char *in,  unsigned long inlen,
								 char *out, unsigned long *outlen);

int base64_decode(const char *in,  unsigned long inlen,
						unsigned char *out, unsigned long *outlen);
int base64_strict_decode(const char *in,  unsigned long inlen,
						unsigned char *out, unsigned long *outlen);
int base64_sane_decode(const char *in,  unsigned long inlen,
						unsigned char *out, unsigned long *outlen);
#endif

#ifdef LFH_BASE64_URL
int base64url_encode(const unsigned char *in,  unsigned long inlen,
									char *out, unsigned long *outlen);
int base64url_strict_encode(const unsigned char *in,  unsigned long inlen,
											char *out, unsigned long *outlen);

int base64url_decode(const char *in,  unsigned long inlen,
						unsigned char *out, unsigned long *outlen);
int base64url_strict_decode(const char *in,  unsigned long inlen,
						unsigned char *out, unsigned long *outlen);
int base64url_sane_decode(const char *in,  unsigned long inlen,
						unsigned char *out, unsigned long *outlen);
#endif

#ifdef LFH_BASE32
typedef enum {
	BASE32_RFC4648   = 0,
	BASE32_BASE32HEX = 1,
	BASE32_ZBASE32   = 2,
	BASE32_CROCKFORD = 3
} base32_alphabet;
int base32_encode(const unsigned char *in,  unsigned long inlen,
								 char *out, unsigned long *outlen,
						base32_alphabet id);
int base32_decode(const          char *in,  unsigned long inlen,
						unsigned char *out, unsigned long *outlen,
						base32_alphabet id);
#endif

#ifdef LFH_BASE16
int base16_encode(const unsigned char *in,  unsigned long  inlen,
								 char *out, unsigned long *outlen,
						unsigned int   options);
int base16_decode(const          char *in,  unsigned long  inlen,
						unsigned char *out, unsigned long *outlen);
#endif

#ifdef LFH_BCRYPT
int bcrypt_pbkdf_openbsd(const          void *secret, unsigned long secret_len,
						 const unsigned char *salt,   unsigned long salt_len,
								unsigned int  rounds,            int hash_idx,
								unsigned char *out,    unsigned long *outlen);
#endif

#ifdef LFH_HKDF

int hkdf_test(void);

int hkdf_extract(int hash_idx,
				 const unsigned char *salt, unsigned long saltlen,
				 const unsigned char *in,   unsigned long inlen,
						unsigned char *out,  unsigned long *outlen);

int hkdf_expand(int hash_idx,
				const unsigned char *info, unsigned long infolen,
				const unsigned char *in,   unsigned long inlen,
						unsigned char *out,  unsigned long outlen);

int hkdf(int hash_idx,
		 const unsigned char *salt, unsigned long saltlen,
		 const unsigned char *info, unsigned long infolen,
		 const unsigned char *in,   unsigned long inlen,
				unsigned char *out,  unsigned long outlen);

#endif  /* LFH_HKDF */

int mem_neq(const void *a, const void *b, size_t len);
void zeromem(volatile void *out, size_t outlen);
void burn_stack(unsigned long len);

const char *error_to_string(int err);

extern const char *crypt_build_settings;

int crypt_fsa(void *mp, ...);

int crypt_get_constant(const char* namein, int *valueout);
int crypt_list_all_constants(char *names_list, unsigned int *names_list_size);

int crypt_get_size(const char* namein, unsigned int *sizeout);
int crypt_list_all_sizes(char *names_list, unsigned int *names_list_size);

#ifdef LTM_DESC
LFH_DEPRECATED(crypt_mp_init) void init_LTM(void);
#endif
#ifdef TFM_DESC
LFH_DEPRECATED(crypt_mp_init) void init_TFM(void);
#endif
#ifdef GMP_DESC
LFH_DEPRECATED(crypt_mp_init) void init_GMP(void);
#endif
int crypt_mp_init(const char* mpi);

#ifdef LFH_ADLER32
typedef struct adler32_state_s
{
	unsigned short s[2];
} adler32_state;

void adler32_init(adler32_state *ctx);
void adler32_update(adler32_state *ctx, const unsigned char *input, unsigned long length);
void adler32_finish(const adler32_state *ctx, void *hash, unsigned long size);
int adler32_test(void);
#endif

#ifdef LFH_CRC32
typedef struct crc32_state_s
{
	ulong32 crc;
} crc32_state;

void crc32_init(crc32_state *ctx);
void crc32_update(crc32_state *ctx, const unsigned char *input, unsigned long length);
void crc32_finish(const crc32_state *ctx, void *hash, unsigned long size);
int crc32_test(void);
#endif

#ifdef LFH_PADDING

enum padding_type {
	LFH_PAD_PKCS7        = 0x0000U,
#ifdef LFH_RNG_GET_BYTES
	LFH_PAD_ISO_10126    = 0x1000U,
#endif
	LFH_PAD_ANSI_X923    = 0x2000U,
	/* The following padding modes don't contain the padding
	* length as last byte of the padding.
	*/
	LFH_PAD_ONE_AND_ZERO = 0x8000U,
	LFH_PAD_ZERO         = 0x9000U,
	LFH_PAD_ZERO_ALWAYS  = 0xA000U,
};

int padding_pad(unsigned char *data, unsigned long length, unsigned long* padded_length, unsigned long mode);
int padding_depad(const unsigned char *data, unsigned long *length, unsigned long mode);
#endif  /* LFH_PADDING */

#ifdef LFH_SSH
typedef enum ssh_data_type_ {
	LFH_SSHDATA_EOL,
	LFH_SSHDATA_BYTE,
	LFH_SSHDATA_BOOLEAN,
	LFH_SSHDATA_UINT32,
	LFH_SSHDATA_UINT64,
	LFH_SSHDATA_STRING,
	LFH_SSHDATA_MPINT,
	LFH_SSHDATA_NAMELIST,
} ssh_data_type;

int ssh_encode_sequence_multi(unsigned char *out, unsigned long *outlen, ...);
int ssh_decode_sequence_multi(const unsigned char *in, unsigned long *inlen, ...);
#endif /* LFH_SSH */

int compare_testvector(const void* is, const unsigned long is_len, const void* should, const unsigned long should_len, const char* what, int which);

#ifdef __cplusplus
	}
#endif

#endif /* FREEHASH_H_ */

