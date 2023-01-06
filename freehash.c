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

#include "freehash.h"

#if ARGTYPE == 0

#include <signal.h>

LFH_NORETURN void crypt_argchk(const char *v, const char *s, int d);
#define LFH_ARGCHK(x) do { if (!(x)) { crypt_argchk(#x, __FILE__, __LINE__); } }while(0)
#define LFH_ARGCHKVD(x) do { if (!(x)) { crypt_argchk(#x, __FILE__, __LINE__); } }while(0)

#elif ARGTYPE == 1

#define LFH_ARGCHK(x) assert((x))
#define LFH_ARGCHKVD(x) LFH_ARGCHK(x)

#elif ARGTYPE == 2

#define LFH_ARGCHK(x) if (!(x)) { fprintf(stderr, "\nwarning: ARGCHK failed at %s:%d\n", __FILE__, __LINE__); }
#define LFH_ARGCHKVD(x) LFH_ARGCHK(x)

#elif ARGTYPE == 3

#define LFH_ARGCHK(x) LFH_UNUSED_PARAM(x)
#define LFH_ARGCHKVD(x) LFH_ARGCHK(x)

#elif ARGTYPE == 4

#define LFH_ARGCHK(x)   if (!(x)) return CRYPT_INVALID_ARG;
#define LFH_ARGCHKVD(x) if (!(x)) return;

#endif

#ifdef ENDIAN_NEUTRAL

#define STORE32L(x, y) \
	do { (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255); \
		(y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); } while(0)

#define LOAD32L(x, y) \
	do { x = ((ulong32)((y)[3] & 255)<<24) | \
			((ulong32)((y)[2] & 255)<<16) | \
			((ulong32)((y)[1] & 255)<<8)  | \
			((ulong32)((y)[0] & 255)); } while(0)

#define STORE64L(x, y) \
	do { (y)[7] = (unsigned char)(((x)>>56)&255); (y)[6] = (unsigned char)(((x)>>48)&255); \
		(y)[5] = (unsigned char)(((x)>>40)&255); (y)[4] = (unsigned char)(((x)>>32)&255); \
		(y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255); \
		(y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); } while(0)

#define LOAD64L(x, y) \
	do { x = (((ulong64)((y)[7] & 255))<<56)|(((ulong64)((y)[6] & 255))<<48)| \
			(((ulong64)((y)[5] & 255))<<40)|(((ulong64)((y)[4] & 255))<<32)| \
			(((ulong64)((y)[3] & 255))<<24)|(((ulong64)((y)[2] & 255))<<16)| \
			(((ulong64)((y)[1] & 255))<<8)|(((ulong64)((y)[0] & 255))); } while(0)

#define STORE32H(x, y) \
	do { (y)[0] = (unsigned char)(((x)>>24)&255); (y)[1] = (unsigned char)(((x)>>16)&255); \
		(y)[2] = (unsigned char)(((x)>>8)&255); (y)[3] = (unsigned char)((x)&255); } while(0)

#define LOAD32H(x, y) \
	do { x = ((ulong32)((y)[0] & 255)<<24) | \
			((ulong32)((y)[1] & 255)<<16) | \
			((ulong32)((y)[2] & 255)<<8)  | \
			((ulong32)((y)[3] & 255)); } while(0)

#define STORE64H(x, y) \
do { (y)[0] = (unsigned char)(((x)>>56)&255); (y)[1] = (unsigned char)(((x)>>48)&255); \
	 (y)[2] = (unsigned char)(((x)>>40)&255); (y)[3] = (unsigned char)(((x)>>32)&255); \
	 (y)[4] = (unsigned char)(((x)>>24)&255); (y)[5] = (unsigned char)(((x)>>16)&255); \
	 (y)[6] = (unsigned char)(((x)>>8)&255); (y)[7] = (unsigned char)((x)&255); } while(0)

#define LOAD64H(x, y) \
do { x = (((ulong64)((y)[0] & 255))<<56)|(((ulong64)((y)[1] & 255))<<48) | \
		 (((ulong64)((y)[2] & 255))<<40)|(((ulong64)((y)[3] & 255))<<32) | \
		 (((ulong64)((y)[4] & 255))<<24)|(((ulong64)((y)[5] & 255))<<16) | \
		 (((ulong64)((y)[6] & 255))<<8)|(((ulong64)((y)[7] & 255))); } while(0)

#elif defined(ENDIAN_LITTLE)

#ifdef LFH_HAVE_BSWAP_BUILTIN

#define STORE32H(x, y) \
do { ulong32 ttt = __builtin_bswap32 ((x)); \
		XMEMCPY ((y), &ttt, 4); } while(0)

#define LOAD32H(x, y) \
do { XMEMCPY (&(x), (y), 4); \
		(x) = __builtin_bswap32 ((x)); } while(0)

#elif !defined(LFH_NO_BSWAP) && (defined(INTEL_CC) || (defined(__GNUC__) && (defined(__DJGPP__) || defined(__CYGWIN__) || defined(__MINGW32__) || defined(__i386__) || defined(__x86_64__))))

#define STORE32H(x, y) \
asm __volatile__ ( \
	"bswapl %0     \n\t" \
	"movl   %0,(%1)\n\t" \
	"bswapl %0     \n\t" \
		::"r"(x), "r"(y): "memory");

#define LOAD32H(x, y) \
asm __volatile__ ( \
	"movl (%1),%0\n\t" \
	"bswapl %0\n\t" \
	:"=r"(x): "r"(y): "memory");

#else

#define STORE32H(x, y) \
	do { (y)[0] = (unsigned char)(((x)>>24)&255); (y)[1] = (unsigned char)(((x)>>16)&255); \
		(y)[2] = (unsigned char)(((x)>>8)&255); (y)[3] = (unsigned char)((x)&255); } while(0)

#define LOAD32H(x, y) \
	do { x = ((ulong32)((y)[0] & 255)<<24) | \
			((ulong32)((y)[1] & 255)<<16) | \
			((ulong32)((y)[2] & 255)<<8)  | \
			((ulong32)((y)[3] & 255)); } while(0)

#endif

#ifdef LFH_HAVE_BSWAP_BUILTIN

#define STORE64H(x, y) \
do { ulong64 ttt = __builtin_bswap64 ((x)); \
		XMEMCPY ((y), &ttt, 8); } while(0)

#define LOAD64H(x, y) \
do { XMEMCPY (&(x), (y), 8); \
		(x) = __builtin_bswap64 ((x)); } while(0)

#elif !defined(LFH_NO_BSWAP) && (defined(__GNUC__) && defined(__x86_64__))

#define STORE64H(x, y) \
asm __volatile__ ( \
	"bswapq %0     \n\t" \
	"movq   %0,(%1)\n\t" \
	"bswapq %0     \n\t" \
	::"r"(x), "r"(y): "memory");

#define LOAD64H(x, y) \
asm __volatile__ ( \
	"movq (%1),%0\n\t" \
	"bswapq %0\n\t" \
	:"=r"(x): "r"(y): "memory");

#else

#define STORE64H(x, y) \
do { (y)[0] = (unsigned char)(((x)>>56)&255); (y)[1] = (unsigned char)(((x)>>48)&255); \
	 (y)[2] = (unsigned char)(((x)>>40)&255); (y)[3] = (unsigned char)(((x)>>32)&255); \
	 (y)[4] = (unsigned char)(((x)>>24)&255); (y)[5] = (unsigned char)(((x)>>16)&255); \
	 (y)[6] = (unsigned char)(((x)>>8)&255); (y)[7] = (unsigned char)((x)&255); } while(0)

#define LOAD64H(x, y) \
do { x = (((ulong64)((y)[0] & 255))<<56)|(((ulong64)((y)[1] & 255))<<48) | \
		 (((ulong64)((y)[2] & 255))<<40)|(((ulong64)((y)[3] & 255))<<32) | \
		 (((ulong64)((y)[4] & 255))<<24)|(((ulong64)((y)[5] & 255))<<16) | \
		 (((ulong64)((y)[6] & 255))<<8)|(((ulong64)((y)[7] & 255))); } while(0)

#endif

#ifdef ENDIAN_32BITWORD

#define STORE32L(x, y) \
	do { ulong32  ttt = (x); XMEMCPY(y, &ttt, 4); } while(0)

#define LOAD32L(x, y) \
	do { XMEMCPY(&(x), y, 4); } while(0)

#define STORE64L(x, y) \
	do { (y)[7] = (unsigned char)(((x)>>56)&255); (y)[6] = (unsigned char)(((x)>>48)&255); \
		(y)[5] = (unsigned char)(((x)>>40)&255); (y)[4] = (unsigned char)(((x)>>32)&255); \
		(y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255); \
		(y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); } while(0)

#define LOAD64L(x, y) \
	do { x = (((ulong64)((y)[7] & 255))<<56)|(((ulong64)((y)[6] & 255))<<48)| \
			(((ulong64)((y)[5] & 255))<<40)|(((ulong64)((y)[4] & 255))<<32)| \
			(((ulong64)((y)[3] & 255))<<24)|(((ulong64)((y)[2] & 255))<<16)| \
			(((ulong64)((y)[1] & 255))<<8)|(((ulong64)((y)[0] & 255))); } while(0)

#else /* 64-bit words then  */

#define STORE32L(x, y) \
	do { ulong32 ttt = (x); XMEMCPY(y, &ttt, 4); } while(0)

#define LOAD32L(x, y) \
	do { XMEMCPY(&(x), y, 4); x &= 0xFFFFFFFF; } while(0)

#define STORE64L(x, y) \
	do { ulong64 ttt = (x); XMEMCPY(y, &ttt, 8); } while(0)

#define LOAD64L(x, y) \
	do { XMEMCPY(&(x), y, 8); } while(0)

#endif /* ENDIAN_64BITWORD */

#elif defined(ENDIAN_BIG)

#define STORE32L(x, y) \
	do { (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255); \
		(y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); } while(0)

#define LOAD32L(x, y) \
	do { x = ((ulong32)((y)[3] & 255)<<24) | \
			((ulong32)((y)[2] & 255)<<16) | \
			((ulong32)((y)[1] & 255)<<8)  | \
			((ulong32)((y)[0] & 255)); } while(0)

#define STORE64L(x, y) \
do { (y)[7] = (unsigned char)(((x)>>56)&255); (y)[6] = (unsigned char)(((x)>>48)&255); \
	 (y)[5] = (unsigned char)(((x)>>40)&255); (y)[4] = (unsigned char)(((x)>>32)&255); \
	 (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255); \
	 (y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); } while(0)

#define LOAD64L(x, y) \
do { x = (((ulong64)((y)[7] & 255))<<56)|(((ulong64)((y)[6] & 255))<<48) | \
		 (((ulong64)((y)[5] & 255))<<40)|(((ulong64)((y)[4] & 255))<<32) | \
		 (((ulong64)((y)[3] & 255))<<24)|(((ulong64)((y)[2] & 255))<<16) | \
		 (((ulong64)((y)[1] & 255))<<8)|(((ulong64)((y)[0] & 255))); } while(0)

#ifdef ENDIAN_32BITWORD

#define STORE32H(x, y) \
	do { ulong32 ttt = (x); XMEMCPY(y, &ttt, 4); } while(0)

#define LOAD32H(x, y) \
	do { XMEMCPY(&(x), y, 4); } while(0)

#define STORE64H(x, y) \
	do { (y)[0] = (unsigned char)(((x)>>56)&255); (y)[1] = (unsigned char)(((x)>>48)&255); \
		(y)[2] = (unsigned char)(((x)>>40)&255); (y)[3] = (unsigned char)(((x)>>32)&255); \
		(y)[4] = (unsigned char)(((x)>>24)&255); (y)[5] = (unsigned char)(((x)>>16)&255); \
		(y)[6] = (unsigned char)(((x)>>8)&255);  (y)[7] = (unsigned char)((x)&255); } while(0)

#define LOAD64H(x, y) \
	do { x = (((ulong64)((y)[0] & 255))<<56)|(((ulong64)((y)[1] & 255))<<48)| \
			(((ulong64)((y)[2] & 255))<<40)|(((ulong64)((y)[3] & 255))<<32)| \
			(((ulong64)((y)[4] & 255))<<24)|(((ulong64)((y)[5] & 255))<<16)| \
			(((ulong64)((y)[6] & 255))<<8)| (((ulong64)((y)[7] & 255))); } while(0)

#else /* 64-bit words then  */

#define STORE32H(x, y) \
	do { ulong32 ttt = (x); XMEMCPY(y, &ttt, 4); } while(0)

#define LOAD32H(x, y) \
	do { XMEMCPY(&(x), y, 4); x &= 0xFFFFFFFF; } while(0)

#define STORE64H(x, y) \
	do { ulong64 ttt = (x); XMEMCPY(y, &ttt, 8); } while(0)

#define LOAD64H(x, y) \
	do { XMEMCPY(&(x), y, 8); } while(0)

#endif /* ENDIAN_64BITWORD */
#endif /* ENDIAN_BIG */

#define BSWAP(x)  ( ((x>>24)&0x000000FFUL) | ((x<<24)&0xFF000000UL)  | \
					((x>>8)&0x0000FF00UL)  | ((x<<8)&0x00FF0000UL) )

#if defined(_MSC_VER)
#define LFH_ROx_BUILTIN

#include <stdlib.h>
#pragma intrinsic(_rotr,_rotl)
#define ROR(x,n) _rotr(x,n)
#define ROL(x,n) _rotl(x,n)
#define RORc(x,n) ROR(x,n)
#define ROLc(x,n) ROL(x,n)

#elif defined(LFH_HAVE_ROTATE_BUILTIN)
#define LFH_ROx_BUILTIN

#define ROR(x,n) __builtin_rotateright32(x,n)
#define ROL(x,n) __builtin_rotateleft32(x,n)
#define ROLc(x,n) ROL(x,n)
#define RORc(x,n) ROR(x,n)

#elif !defined(__STRICT_ANSI__) && defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__)) && !defined(INTEL_CC) && !defined(LFH_NO_ASM)
#define LFH_ROx_ASM

static inline ulong32 ROL(ulong32 word, int i)
{
	asm ("roll %%cl,%0"
		:"=r" (word)
		:"0" (word),"c" (i));
	return word;
}

static inline ulong32 ROR(ulong32 word, int i)
{
	asm ("rorl %%cl,%0"
		:"=r" (word)
		:"0" (word),"c" (i));
	return word;
}

#ifndef LFH_NO_ROLC

#define ROLc(word,i) ({ \
	ulong32 ROLc_tmp = (word); \
	__asm__ ("roll %2, %0" : \
			"=r" (ROLc_tmp) : \
			"0" (ROLc_tmp), \
			"I" (i)); \
			ROLc_tmp; \
	})
#define RORc(word,i) ({ \
	ulong32 RORc_tmp = (word); \
	__asm__ ("rorl %2, %0" : \
			"=r" (RORc_tmp) : \
			"0" (RORc_tmp), \
			"I" (i)); \
			RORc_tmp; \
	})

#else

#define ROLc ROL
#define RORc ROR

#endif

#elif !defined(__STRICT_ANSI__) && defined(LFH_PPC32)
#define LFH_ROx_ASM

static inline ulong32 ROL(ulong32 word, int i)
{
	asm ("rotlw %0,%0,%2"
		:"=r" (word)
		:"0" (word),"r" (i));
	return word;
}

static inline ulong32 ROR(ulong32 word, int i)
{
	asm ("rotlw %0,%0,%2"
		:"=r" (word)
		:"0" (word),"r" (32-i));
	return word;
}

#ifndef LFH_NO_ROLC

static inline ulong32 ROLc(ulong32 word, const int i)
{
	asm ("rotlwi %0,%0,%2"
		:"=r" (word)
		:"0" (word),"I" (i));
	return word;
}

static inline ulong32 RORc(ulong32 word, const int i)
{
	asm ("rotrwi %0,%0,%2"
		:"=r" (word)
		:"0" (word),"I" (i));
	return word;
}

#else

#define ROLc ROL
#define RORc ROR

#endif

#else

#define ROL(x, y) ( (((ulong32)(x)<<(ulong32)((y)&31)) | (((ulong32)(x)&0xFFFFFFFFUL)>>(ulong32)((32-((y)&31))&31))) & 0xFFFFFFFFUL)
#define ROR(x, y) ( ((((ulong32)(x)&0xFFFFFFFFUL)>>(ulong32)((y)&31)) | ((ulong32)(x)<<(ulong32)((32-((y)&31))&31))) & 0xFFFFFFFFUL)
#define ROLc(x, y) ( (((ulong32)(x)<<(ulong32)((y)&31)) | (((ulong32)(x)&0xFFFFFFFFUL)>>(ulong32)((32-((y)&31))&31))) & 0xFFFFFFFFUL)
#define RORc(x, y) ( ((((ulong32)(x)&0xFFFFFFFFUL)>>(ulong32)((y)&31)) | ((ulong32)(x)<<(ulong32)((32-((y)&31))&31))) & 0xFFFFFFFFUL)

#endif

#if defined(_MSC_VER)

#include <stdlib.h>
#pragma intrinsic(_rotr64,_rotr64)
#define ROR64(x,n) _rotr64(x,n)
#define ROL64(x,n) _rotl64(x,n)
#define ROR64c(x,n) ROR64(x,n)
#define ROL64c(x,n) ROL64(x,n)

#elif defined(LFH_HAVE_ROTATE_BUILTIN)

#define ROR64(x,n) __builtin_rotateright64(x,n)
#define ROL64(x,n) __builtin_rotateleft64(x,n)
#define ROR64c(x,n) ROR64(x,n)
#define ROL64c(x,n) ROL64(x,n)

#elif !defined(__STRICT_ANSI__) && defined(__GNUC__) && defined(__x86_64__) && !defined(INTEL_CC) && !defined(LFH_NO_ASM)

static inline ulong64 ROL64(ulong64 word, int i)
{
	asm("rolq %%cl,%0"
		:"=r" (word)
		:"0" (word),"c" (i));
	return word;
}

static inline ulong64 ROR64(ulong64 word, int i)
{
	asm("rorq %%cl,%0"
		:"=r" (word)
		:"0" (word),"c" (i));
	return word;
}

#ifndef LFH_NO_ROLC

#define ROL64c(word,i) ({ \
	ulong64 ROL64c_tmp = word; \
	__asm__ ("rolq %2, %0" : \
			"=r" (ROL64c_tmp) : \
			"0" (ROL64c_tmp), \
			"J" (i)); \
			ROL64c_tmp; \
	})
#define ROR64c(word,i) ({ \
	ulong64 ROR64c_tmp = word; \
	__asm__ ("rorq %2, %0" : \
			"=r" (ROR64c_tmp) : \
			"0" (ROR64c_tmp), \
			"J" (i)); \
			ROR64c_tmp; \
	})

#else /* LFH_NO_ROLC */

#define ROL64c ROL64
#define ROR64c ROR64

#endif

#else /* Not x86_64  */

#define ROL64(x, y) \
	( (((x)<<((ulong64)(y)&63)) | \
		(((x)&CONST64(0xFFFFFFFFFFFFFFFF))>>(((ulong64)64-((y)&63))&63))) & CONST64(0xFFFFFFFFFFFFFFFF))

#define ROR64(x, y) \
	( ((((x)&CONST64(0xFFFFFFFFFFFFFFFF))>>((ulong64)(y)&CONST64(63))) | \
		((x)<<(((ulong64)64-((y)&63))&63))) & CONST64(0xFFFFFFFFFFFFFFFF))

#define ROL64c(x, y) \
	( (((x)<<((ulong64)(y)&63)) | \
		(((x)&CONST64(0xFFFFFFFFFFFFFFFF))>>(((ulong64)64-((y)&63))&63))) & CONST64(0xFFFFFFFFFFFFFFFF))

#define ROR64c(x, y) \
	( ((((x)&CONST64(0xFFFFFFFFFFFFFFFF))>>((ulong64)(y)&CONST64(63))) | \
		((x)<<(((ulong64)64-((y)&63))&63))) & CONST64(0xFFFFFFFFFFFFFFFF))

#endif

#ifndef MAX
	#define MAX(x, y) ( ((x)>(y))?(x):(y) )
#endif

#ifndef MIN
	#define MIN(x, y) ( ((x)<(y))?(x):(y) )
#endif

#ifndef LFH_UNUSED_PARAM
	#define LFH_UNUSED_PARAM(x) (void)(x)
#endif

#if defined(_MSC_VER) && _MSC_VER < 1900
#define snprintf _snprintf
#endif

#define HASH_PROCESS(func_name, compress_name, state_var, block_size) \
int func_name (hash_state * md, const unsigned char *in, unsigned long inlen) \
{ \
	unsigned long n; \
	int           err; \
	LFH_ARGCHK(md != NULL); \
	LFH_ARGCHK(in != NULL); \
	if (md-> state_var .curlen > sizeof(md-> state_var .buf)) { \
		return CRYPT_INVALID_ARG; \
	} \
	if (((md-> state_var .length + inlen * 8) < md-> state_var .length) \
			|| ((inlen * 8) < inlen)) { \
		return CRYPT_HASH_OVERFLOW; \
	} \
	while (inlen > 0) { \
		if (md-> state_var .curlen == 0 && inlen >= block_size) { \
			if ((err = compress_name (md, in)) != CRYPT_OK) { \
				return err; \
			} \
			md-> state_var .length += block_size * 8; \
			in             += block_size; \
			inlen          -= block_size; \
		} else { \
			n = MIN(inlen, (block_size - md-> state_var .curlen)); \
			XMEMCPY(md-> state_var .buf + md-> state_var.curlen, in, (size_t)n); \
			md-> state_var .curlen += n; \
			in             += n; \
			inlen          -= n; \
			if (md-> state_var .curlen == block_size) { \
				if ((err = compress_name (md, md-> state_var .buf)) != CRYPT_OK) { \
				 return err; \
				} \
				md-> state_var .length += 8*block_size; \
				md-> state_var .curlen = 0; \
			} \
		} \
	} \
	return CRYPT_OK; \
}

/**
	@param md2.c
	LFH_MD2 (RFC 1319) hash function implementation by Tom St Denis
*/

#ifdef LFH_MD2

const struct lfh_hash_descriptor md2_desc =
{
	"md2",
	7,
	16,
	16,

	{ 1, 2, 840, 113549, 2, 2,  },
	6,

	&md2_init,
	&md2_process,
	&md2_done,
	&md2_test,
	NULL
};

static const unsigned char PI_SUBST[256] = {
	41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
	19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
	76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
	138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
	245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
	148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
	39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
	181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
	150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
	112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
	96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
	85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
	234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
	129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
	8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
	203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
	166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
	31, 26, 219, 153, 141, 51, 159, 17, 131, 20
};

static void s_md2_update_chksum(hash_state *md)
{
	int j;
	unsigned char L;
	L = md->md2.chksum[15];
	for (j = 0; j < 16; j++) {

/* caution, the RFC says its "C[j] = S[M[i*16+j] xor L]" but the reference source code [and test vectors] say
	otherwise.
*/
		L = (md->md2.chksum[j] ^= PI_SUBST[(int)(md->md2.buf[j] ^ L)] & 255);
	}
}

static void s_md2_compress(hash_state *md)
{
	int j, k;
	unsigned char t;

	for (j = 0; j < 16; j++) {
		md->md2.X[16+j] = md->md2.buf[j];
		md->md2.X[32+j] = md->md2.X[j] ^ md->md2.X[16+j];
	}

	t = (unsigned char)0;

	for (j = 0; j < 18; j++) {
		for (k = 0; k < 48; k++) {
			t = (md->md2.X[k] ^= PI_SUBST[(int)(t & 255)]);
		}
		t = (t + (unsigned char)j) & 255;
	}
}

/**
	Initialize the hash state
	@param md   The hash state you wish to initialize
	@return CRYPT_OK if successful
*/
int md2_init(hash_state *md)
{
	LFH_ARGCHK(md != NULL);

	zeromem(md->md2.X, sizeof(md->md2.X));
	zeromem(md->md2.chksum, sizeof(md->md2.chksum));
	zeromem(md->md2.buf, sizeof(md->md2.buf));
	md->md2.curlen = 0;
	return CRYPT_OK;
}

/**
	Process a block of memory though the hash
	@param md     The hash state
	@param in     The data to hash
	@param inlen  The length of the data (octets)
	@return CRYPT_OK if successful
*/
int md2_process(hash_state *md, const unsigned char *in, unsigned long inlen)
{
	unsigned long n;
	LFH_ARGCHK(md != NULL);
	LFH_ARGCHK(in != NULL);
	if (md-> md2 .curlen > sizeof(md-> md2 .buf)) {
		return CRYPT_INVALID_ARG;
	}
	while (inlen > 0) {
		n = MIN(inlen, (16 - md->md2.curlen));
		XMEMCPY(md->md2.buf + md->md2.curlen, in, (size_t)n);
		md->md2.curlen += n;
		in             += n;
		inlen          -= n;

		if (md->md2.curlen == 16) {
			s_md2_compress(md);
			s_md2_update_chksum(md);
			md->md2.curlen = 0;
		}
	}
	return CRYPT_OK;
}

/**
	Terminate the hash to get the digest
	@param md  The hash state
	@param out [out] The destination of the hash (16 bytes)
	@return CRYPT_OK if successful
*/
int md2_done(hash_state * md, unsigned char *out)
{
	unsigned long i, k;

	LFH_ARGCHK(md  != NULL);
	LFH_ARGCHK(out != NULL);

	if (md->md2.curlen >= sizeof(md->md2.buf)) {
		return CRYPT_INVALID_ARG;
	}

	k = 16 - md->md2.curlen;
	for (i = md->md2.curlen; i < 16; i++) {
		md->md2.buf[i] = (unsigned char)k;
	}

	s_md2_compress(md);
	s_md2_update_chksum(md);

	XMEMCPY(md->md2.buf, md->md2.chksum, 16);
	s_md2_compress(md);

	XMEMCPY(out, md->md2.X, 16);

#ifdef LFH_CLEAN_STACK
	zeromem(md, sizeof(hash_state));
#endif
	return CRYPT_OK;
}

/**
	Self-test the hash
	@return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int md2_test(void)
{
 #ifndef LFH_TEST
	return CRYPT_NOP;
 #else
	static const struct {
		const char *msg;
		unsigned char hash[16];
	} tests[] = {
		{ "",
		{0x83,0x50,0xe5,0xa3,0xe2,0x4c,0x15,0x3d,
		 0xf2,0x27,0x5c,0x9f,0x80,0x69,0x27,0x73
		}
		},
		{ "a",
		{0x32,0xec,0x01,0xec,0x4a,0x6d,0xac,0x72,
		 0xc0,0xab,0x96,0xfb,0x34,0xc0,0xb5,0xd1
		}
		},
		{ "message digest",
		{0xab,0x4f,0x49,0x6b,0xfb,0x2a,0x53,0x0b,
		 0x21,0x9f,0xf3,0x30,0x31,0xfe,0x06,0xb0
		}
		},
		{ "abcdefghijklmnopqrstuvwxyz",
		{0x4e,0x8d,0xdf,0xf3,0x65,0x02,0x92,0xab,
		 0x5a,0x41,0x08,0xc3,0xaa,0x47,0x94,0x0b
		}
		},
		{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		{0xda,0x33,0xde,0xf2,0xa4,0x2d,0xf1,0x39,
		 0x75,0x35,0x28,0x46,0xc3,0x03,0x38,0xcd
		}
		},
		{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
		{0xd5,0x97,0x6f,0x79,0xd8,0x3d,0x3a,0x0d,
		 0xc9,0x80,0x6c,0x3c,0x66,0xf3,0xef,0xd8
		}
		}
	};

	int i;
	unsigned char tmp[16];
	hash_state md;

	for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); i++) {
		md2_init(&md);
		md2_process(&md, (unsigned char*)tests[i].msg, (unsigned long)XSTRLEN(tests[i].msg));
		md2_done(&md, tmp);
		if (compare_testvector(tmp, sizeof(tmp), tests[i].hash, sizeof(tests[i].hash), "MD2", i)) {
			return CRYPT_FAIL_TESTVECTOR;
		}
	}
	return CRYPT_OK;
	#endif
}

#endif

/**
	@param md4.c
	Submitted by Dobes Vandermeer  (dobes@smartt.com)
*/

#ifdef LFH_MD4

const struct lfh_hash_descriptor md4_desc =
{
	"md4",
	6,
	16,
	64,

	{ 1, 2, 840, 113549, 2, 4,  },
	6,

	&md4_init,
	&md4_process,
	&md4_done,
	&md4_test,
	NULL
};

#define md4_S11 3
#define md4_S12 7
#define md4_S13 11
#define md4_S14 19
#define md4_S21 3
#define md4_S22 5
#define md4_S23 9
#define md4_S24 13
#define md4_S31 3
#define md4_S32 9
#define md4_S33 11
#define md4_S34 15

#define md4_F(x, y, z) (z ^ (x & (y ^ z)))
#define md4_G(x, y, z) ((x & y) | (z & (x | y)))
#define md4_H(x, y, z) ((x) ^ (y) ^ (z))

#define ROTATE_LEFT(x, n) ROLc(x, n)

#define md4_FF(a, b, c, d, x, s) { \
	(a) += md4_F ((b), (c), (d)) + (x); \
	(a) = ROTATE_LEFT ((a), (s)); \
	}
#define md4_GG(a, b, c, d, x, s) { \
	(a) += md4_G ((b), (c), (d)) + (x) + 0x5a827999UL; \
	(a) = ROTATE_LEFT ((a), (s)); \
	}
#define md4_HH(a, b, c, d, x, s) { \
	(a) += md4_H ((b), (c), (d)) + (x) + 0x6ed9eba1UL; \
	(a) = ROTATE_LEFT ((a), (s)); \
	}

#ifdef LFH_CLEAN_STACK
static int ss_md4_compress(hash_state *md, const unsigned char *buf)
#else
static int  s_md4_compress(hash_state *md, const unsigned char *buf)
#endif
{
	ulong32 x[16], a, b, c, d;
	int i;

	a = md->md4.state[0];
	b = md->md4.state[1];
	c = md->md4.state[2];
	d = md->md4.state[3];

	for (i = 0; i < 16; i++) {
		LOAD32L(x[i], buf + (4*i));
	}

	md4_FF (a, b, c, d, x[ 0], md4_S11); /* 1 */
	md4_FF (d, a, b, c, x[ 1], md4_S12); /* 2 */
	md4_FF (c, d, a, b, x[ 2], md4_S13); /* 3 */
	md4_FF (b, c, d, a, x[ 3], md4_S14); /* 4 */
	md4_FF (a, b, c, d, x[ 4], md4_S11); /* 5 */
	md4_FF (d, a, b, c, x[ 5], md4_S12); /* 6 */
	md4_FF (c, d, a, b, x[ 6], md4_S13); /* 7 */
	md4_FF (b, c, d, a, x[ 7], md4_S14); /* 8 */
	md4_FF (a, b, c, d, x[ 8], md4_S11); /* 9 */
	md4_FF (d, a, b, c, x[ 9], md4_S12); /* 10 */
	md4_FF (c, d, a, b, x[10], md4_S13); /* 11 */
	md4_FF (b, c, d, a, x[11], md4_S14); /* 12 */
	md4_FF (a, b, c, d, x[12], md4_S11); /* 13 */
	md4_FF (d, a, b, c, x[13], md4_S12); /* 14 */
	md4_FF (c, d, a, b, x[14], md4_S13); /* 15 */
	md4_FF (b, c, d, a, x[15], md4_S14); /* 16 */

	md4_GG (a, b, c, d, x[ 0], md4_S21); /* 17 */
	md4_GG (d, a, b, c, x[ 4], md4_S22); /* 18 */
	md4_GG (c, d, a, b, x[ 8], md4_S23); /* 19 */
	md4_GG (b, c, d, a, x[12], md4_S24); /* 20 */
	md4_GG (a, b, c, d, x[ 1], md4_S21); /* 21 */
	md4_GG (d, a, b, c, x[ 5], md4_S22); /* 22 */
	md4_GG (c, d, a, b, x[ 9], md4_S23); /* 23 */
	md4_GG (b, c, d, a, x[13], md4_S24); /* 24 */
	md4_GG (a, b, c, d, x[ 2], md4_S21); /* 25 */
	md4_GG (d, a, b, c, x[ 6], md4_S22); /* 26 */
	md4_GG (c, d, a, b, x[10], md4_S23); /* 27 */
	md4_GG (b, c, d, a, x[14], md4_S24); /* 28 */
	md4_GG (a, b, c, d, x[ 3], md4_S21); /* 29 */
	md4_GG (d, a, b, c, x[ 7], md4_S22); /* 30 */
	md4_GG (c, d, a, b, x[11], md4_S23); /* 31 */
	md4_GG (b, c, d, a, x[15], md4_S24); /* 32 */

	md4_HH (a, b, c, d, x[ 0], md4_S31); /* 33 */
	md4_HH (d, a, b, c, x[ 8], md4_S32); /* 34 */
	md4_HH (c, d, a, b, x[ 4], md4_S33); /* 35 */
	md4_HH (b, c, d, a, x[12], md4_S34); /* 36 */
	md4_HH (a, b, c, d, x[ 2], md4_S31); /* 37 */
	md4_HH (d, a, b, c, x[10], md4_S32); /* 38 */
	md4_HH (c, d, a, b, x[ 6], md4_S33); /* 39 */
	md4_HH (b, c, d, a, x[14], md4_S34); /* 40 */
	md4_HH (a, b, c, d, x[ 1], md4_S31); /* 41 */
	md4_HH (d, a, b, c, x[ 9], md4_S32); /* 42 */
	md4_HH (c, d, a, b, x[ 5], md4_S33); /* 43 */
	md4_HH (b, c, d, a, x[13], md4_S34); /* 44 */
	md4_HH (a, b, c, d, x[ 3], md4_S31); /* 45 */
	md4_HH (d, a, b, c, x[11], md4_S32); /* 46 */
	md4_HH (c, d, a, b, x[ 7], md4_S33); /* 47 */
	md4_HH (b, c, d, a, x[15], md4_S34); /* 48 */

	md->md4.state[0] = md->md4.state[0] + a;
	md->md4.state[1] = md->md4.state[1] + b;
	md->md4.state[2] = md->md4.state[2] + c;
	md->md4.state[3] = md->md4.state[3] + d;

	return CRYPT_OK;
}

#ifdef LFH_CLEAN_STACK
static int s_md4_compress(hash_state *md, const unsigned char *buf)
{
	int err;
	err = ss_md4_compress(md, buf);
	burn_stack(sizeof(ulong32) * 20 + sizeof(int));
	return err;
}
#endif

/**
	Initialize the hash state
	@param md   The hash state you wish to initialize
	@return CRYPT_OK if successful
*/
int md4_init(hash_state * md)
{
	LFH_ARGCHK(md != NULL);
	md->md4.state[0] = 0x67452301UL;
	md->md4.state[1] = 0xefcdab89UL;
	md->md4.state[2] = 0x98badcfeUL;
	md->md4.state[3] = 0x10325476UL;
	md->md4.length  = 0;
	md->md4.curlen  = 0;
	return CRYPT_OK;
}

/**
	Process a block of memory though the hash
	@param md     The hash state
	@param in     The data to hash
	@param inlen  The length of the data (octets)
	@return CRYPT_OK if successful
*/
HASH_PROCESS(md4_process, s_md4_compress, md4, 64)

/**
	Terminate the hash to get the digest
	@param md  The hash state
	@param out [out] The destination of the hash (16 bytes)
	@return CRYPT_OK if successful
*/
int md4_done(hash_state * md, unsigned char *out)
{
	int i;

	LFH_ARGCHK(md  != NULL);
	LFH_ARGCHK(out != NULL);

	if (md->md4.curlen >= sizeof(md->md4.buf)) {
		return CRYPT_INVALID_ARG;
	}

	md->md4.length += md->md4.curlen * 8;

	md->md4.buf[md->md4.curlen++] = (unsigned char)0x80;

	/* if the length is currently above 56 bytes we append zeros
	 * then compress.  Then we can fall back to padding zeros and length
	 * encoding like normal.
	 */
	if (md->md4.curlen > 56) {
		while (md->md4.curlen < 64) {
			md->md4.buf[md->md4.curlen++] = (unsigned char)0;
		}
		s_md4_compress(md, md->md4.buf);
		md->md4.curlen = 0;
	}

	while (md->md4.curlen < 56) {
		md->md4.buf[md->md4.curlen++] = (unsigned char)0;
	}

	STORE64L(md->md4.length, md->md4.buf+56);
	s_md4_compress(md, md->md4.buf);

	for (i = 0; i < 4; i++) {
		STORE32L(md->md4.state[i], out+(4*i));
	}
#ifdef LFH_CLEAN_STACK
	zeromem(md, sizeof(hash_state));
#endif
	return CRYPT_OK;
}

/**
	Self-test the hash
	@return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int md4_test(void)
{
 #ifndef LFH_TEST
	return CRYPT_NOP;
 #else
	static const struct md4_test_case {
		const char *input;
		unsigned char hash[16];
	} tests[] = {
		{ "",
			{0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31,
			0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0} },
		{ "a",
			{0xbd, 0xe5, 0x2c, 0xb3, 0x1d, 0xe3, 0x3e, 0x46,
			0x24, 0x5e, 0x05, 0xfb, 0xdb, 0xd6, 0xfb, 0x24} },
		{ "abc",
			{0xa4, 0x48, 0x01, 0x7a, 0xaf, 0x21, 0xd8, 0x52,
			0x5f, 0xc1, 0x0a, 0xe8, 0x7a, 0xa6, 0x72, 0x9d} },
		{ "message digest",
			{0xd9, 0x13, 0x0a, 0x81, 0x64, 0x54, 0x9f, 0xe8,
			0x18, 0x87, 0x48, 0x06, 0xe1, 0xc7, 0x01, 0x4b} },
		{ "abcdefghijklmnopqrstuvwxyz",
			{0xd7, 0x9e, 0x1c, 0x30, 0x8a, 0xa5, 0xbb, 0xcd,
			0xee, 0xa8, 0xed, 0x63, 0xdf, 0x41, 0x2d, 0xa9} },
		{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			{0x04, 0x3f, 0x85, 0x82, 0xf2, 0x41, 0xdb, 0x35,
			0x1c, 0xe6, 0x27, 0xe1, 0x53, 0xe7, 0xf0, 0xe4} },
		{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
			{0xe3, 0x3b, 0x4d, 0xdc, 0x9c, 0x38, 0xf2, 0x19,
			0x9c, 0x3e, 0x7b, 0x16, 0x4f, 0xcc, 0x05, 0x36} },
	};

	int i;
	unsigned char tmp[16];
	hash_state md;

	for(i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); i++) {
		md4_init(&md);
		md4_process(&md, (unsigned char *)tests[i].input, (unsigned long)XSTRLEN(tests[i].input));
		md4_done(&md, tmp);
		if (compare_testvector(tmp, sizeof(tmp), tests[i].hash, sizeof(tests[i].hash), "MD4", i)) {
			return CRYPT_FAIL_TESTVECTOR;
		}

	}
	return CRYPT_OK;
	#endif
}

#endif

/**
	@file md5.c
	LFH_MD5 hash function by Tom St Denis
*/

#ifdef LFH_MD5

const struct lfh_hash_descriptor md5_desc =
{
	"md5",
	3,
	16,
	64,

	{ 1, 2, 840, 113549, 2, 5,  },
	6,

	&md5_init,
	&md5_process,
	&md5_done,
	&md5_test,
	NULL
};

#define md5_F(x,y,z)  (z ^ (x & (y ^ z)))
#define md5_G(x,y,z)  (y ^ (z & (y ^ x)))
#define md5_H(x,y,z)  (x^y^z)
#define md5_I(x,y,z)  (y^(x|(~z)))

#ifdef LFH_SMALL_CODE

#define md5_FF(a,b,c,d,M,s,t) \
	a = (a + md5_F(b,c,d) + M + t); a = ROL(a, s) + b;

#define md5_GG(a,b,c,d,M,s,t) \
	a = (a + md5_G(b,c,d) + M + t); a = ROL(a, s) + b;

#define md5_HH(a,b,c,d,M,s,t) \
	a = (a + md5_H(b,c,d) + M + t); a = ROL(a, s) + b;

#define md5_II(a,b,c,d,M,s,t) \
	a = (a + md5_I(b,c,d) + M + t); a = ROL(a, s) + b;

static const unsigned char Worder[64] = {
	0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
	1,6,11,0,5,10,15,4,9,14,3,8,13,2,7,12,
	5,8,11,14,1,4,7,10,13,0,3,6,9,12,15,2,
	0,7,14,5,12,3,10,1,8,15,6,13,4,11,2,9
};

static const unsigned char Rorder[64] = {
	7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
	5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
	4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
	6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
};

static const ulong32 Korder[64] = {
0xd76aa478UL, 0xe8c7b756UL, 0x242070dbUL, 0xc1bdceeeUL, 0xf57c0fafUL, 0x4787c62aUL, 0xa8304613UL, 0xfd469501UL,
0x698098d8UL, 0x8b44f7afUL, 0xffff5bb1UL, 0x895cd7beUL, 0x6b901122UL, 0xfd987193UL, 0xa679438eUL, 0x49b40821UL,
0xf61e2562UL, 0xc040b340UL, 0x265e5a51UL, 0xe9b6c7aaUL, 0xd62f105dUL, 0x02441453UL, 0xd8a1e681UL, 0xe7d3fbc8UL,
0x21e1cde6UL, 0xc33707d6UL, 0xf4d50d87UL, 0x455a14edUL, 0xa9e3e905UL, 0xfcefa3f8UL, 0x676f02d9UL, 0x8d2a4c8aUL,
0xfffa3942UL, 0x8771f681UL, 0x6d9d6122UL, 0xfde5380cUL, 0xa4beea44UL, 0x4bdecfa9UL, 0xf6bb4b60UL, 0xbebfbc70UL,
0x289b7ec6UL, 0xeaa127faUL, 0xd4ef3085UL, 0x04881d05UL, 0xd9d4d039UL, 0xe6db99e5UL, 0x1fa27cf8UL, 0xc4ac5665UL,
0xf4292244UL, 0x432aff97UL, 0xab9423a7UL, 0xfc93a039UL, 0x655b59c3UL, 0x8f0ccc92UL, 0xffeff47dUL, 0x85845dd1UL,
0x6fa87e4fUL, 0xfe2ce6e0UL, 0xa3014314UL, 0x4e0811a1UL, 0xf7537e82UL, 0xbd3af235UL, 0x2ad7d2bbUL, 0xeb86d391UL
};

#else

#define md5_FF(a,b,c,d,M,s,t) \
	a = (a + md5_F(b,c,d) + M + t); a = ROLc(a, s) + b;

#define md5_GG(a,b,c,d,M,s,t) \
	a = (a + md5_G(b,c,d) + M + t); a = ROLc(a, s) + b;

#define md5_HH(a,b,c,d,M,s,t) \
	a = (a + md5_H(b,c,d) + M + t); a = ROLc(a, s) + b;

#define md5_II(a,b,c,d,M,s,t) \
	a = (a + md5_I(b,c,d) + M + t); a = ROLc(a, s) + b;

#endif

#ifdef LFH_CLEAN_STACK
static int ss_md5_compress(hash_state *md, const unsigned char *buf)
#else
static int  s_md5_compress(hash_state *md, const unsigned char *buf)
#endif
{
	ulong32 i, W[16], a, b, c, d;
#ifdef LFH_SMALL_CODE
	ulong32 t;
#endif

	for (i = 0; i < 16; i++) {
		LOAD32L(W[i], buf + (4*i));
	}

	a = md->md5.state[0];
	b = md->md5.state[1];
	c = md->md5.state[2];
	d = md->md5.state[3];

#ifdef LFH_SMALL_CODE
	for (i = 0; i < 16; ++i) {
		md5_FF(a,b,c,d,W[Worder[i]],Rorder[i],Korder[i]);
		t = d; d = c; c = b; b = a; a = t;
	}

	for (; i < 32; ++i) {
		md5_GG(a,b,c,d,W[Worder[i]],Rorder[i],Korder[i]);
		t = d; d = c; c = b; b = a; a = t;
	}

	for (; i < 48; ++i) {
		md5_HH(a,b,c,d,W[Worder[i]],Rorder[i],Korder[i]);
		t = d; d = c; c = b; b = a; a = t;
	}

	for (; i < 64; ++i) {
		md5_II(a,b,c,d,W[Worder[i]],Rorder[i],Korder[i]);
		t = d; d = c; c = b; b = a; a = t;
	}

#else
	md5_FF(a,b,c,d,W[0],7,0xd76aa478UL)
	md5_FF(d,a,b,c,W[1],12,0xe8c7b756UL)
	md5_FF(c,d,a,b,W[2],17,0x242070dbUL)
	md5_FF(b,c,d,a,W[3],22,0xc1bdceeeUL)
	md5_FF(a,b,c,d,W[4],7,0xf57c0fafUL)
	md5_FF(d,a,b,c,W[5],12,0x4787c62aUL)
	md5_FF(c,d,a,b,W[6],17,0xa8304613UL)
	md5_FF(b,c,d,a,W[7],22,0xfd469501UL)
	md5_FF(a,b,c,d,W[8],7,0x698098d8UL)
	md5_FF(d,a,b,c,W[9],12,0x8b44f7afUL)
	md5_FF(c,d,a,b,W[10],17,0xffff5bb1UL)
	md5_FF(b,c,d,a,W[11],22,0x895cd7beUL)
	md5_FF(a,b,c,d,W[12],7,0x6b901122UL)
	md5_FF(d,a,b,c,W[13],12,0xfd987193UL)
	md5_FF(c,d,a,b,W[14],17,0xa679438eUL)
	md5_FF(b,c,d,a,W[15],22,0x49b40821UL)
	md5_GG(a,b,c,d,W[1],5,0xf61e2562UL)
	md5_GG(d,a,b,c,W[6],9,0xc040b340UL)
	md5_GG(c,d,a,b,W[11],14,0x265e5a51UL)
	md5_GG(b,c,d,a,W[0],20,0xe9b6c7aaUL)
	md5_GG(a,b,c,d,W[5],5,0xd62f105dUL)
	md5_GG(d,a,b,c,W[10],9,0x02441453UL)
	md5_GG(c,d,a,b,W[15],14,0xd8a1e681UL)
	md5_GG(b,c,d,a,W[4],20,0xe7d3fbc8UL)
	md5_GG(a,b,c,d,W[9],5,0x21e1cde6UL)
	md5_GG(d,a,b,c,W[14],9,0xc33707d6UL)
	md5_GG(c,d,a,b,W[3],14,0xf4d50d87UL)
	md5_GG(b,c,d,a,W[8],20,0x455a14edUL)
	md5_GG(a,b,c,d,W[13],5,0xa9e3e905UL)
	md5_GG(d,a,b,c,W[2],9,0xfcefa3f8UL)
	md5_GG(c,d,a,b,W[7],14,0x676f02d9UL)
	md5_GG(b,c,d,a,W[12],20,0x8d2a4c8aUL)
	md5_HH(a,b,c,d,W[5],4,0xfffa3942UL)
	md5_HH(d,a,b,c,W[8],11,0x8771f681UL)
	md5_HH(c,d,a,b,W[11],16,0x6d9d6122UL)
	md5_HH(b,c,d,a,W[14],23,0xfde5380cUL)
	md5_HH(a,b,c,d,W[1],4,0xa4beea44UL)
	md5_HH(d,a,b,c,W[4],11,0x4bdecfa9UL)
	md5_HH(c,d,a,b,W[7],16,0xf6bb4b60UL)
	md5_HH(b,c,d,a,W[10],23,0xbebfbc70UL)
	md5_HH(a,b,c,d,W[13],4,0x289b7ec6UL)
	md5_HH(d,a,b,c,W[0],11,0xeaa127faUL)
	md5_HH(c,d,a,b,W[3],16,0xd4ef3085UL)
	md5_HH(b,c,d,a,W[6],23,0x04881d05UL)
	md5_HH(a,b,c,d,W[9],4,0xd9d4d039UL)
	md5_HH(d,a,b,c,W[12],11,0xe6db99e5UL)
	md5_HH(c,d,a,b,W[15],16,0x1fa27cf8UL)
	md5_HH(b,c,d,a,W[2],23,0xc4ac5665UL)
	md5_II(a,b,c,d,W[0],6,0xf4292244UL)
	md5_II(d,a,b,c,W[7],10,0x432aff97UL)
	md5_II(c,d,a,b,W[14],15,0xab9423a7UL)
	md5_II(b,c,d,a,W[5],21,0xfc93a039UL)
	md5_II(a,b,c,d,W[12],6,0x655b59c3UL)
	md5_II(d,a,b,c,W[3],10,0x8f0ccc92UL)
	md5_II(c,d,a,b,W[10],15,0xffeff47dUL)
	md5_II(b,c,d,a,W[1],21,0x85845dd1UL)
	md5_II(a,b,c,d,W[8],6,0x6fa87e4fUL)
	md5_II(d,a,b,c,W[15],10,0xfe2ce6e0UL)
	md5_II(c,d,a,b,W[6],15,0xa3014314UL)
	md5_II(b,c,d,a,W[13],21,0x4e0811a1UL)
	md5_II(a,b,c,d,W[4],6,0xf7537e82UL)
	md5_II(d,a,b,c,W[11],10,0xbd3af235UL)
	md5_II(c,d,a,b,W[2],15,0x2ad7d2bbUL)
	md5_II(b,c,d,a,W[9],21,0xeb86d391UL)
#endif

	md->md5.state[0] = md->md5.state[0] + a;
	md->md5.state[1] = md->md5.state[1] + b;
	md->md5.state[2] = md->md5.state[2] + c;
	md->md5.state[3] = md->md5.state[3] + d;

	return CRYPT_OK;
}

#ifdef LFH_CLEAN_STACK
static int s_md5_compress(hash_state *md, const unsigned char *buf)
{
	int err;
	err = ss_md5_compress(md, buf);
	burn_stack(sizeof(ulong32) * 21);
	return err;
}
#endif

/**
	Initialize the hash state
	@param md   The hash state you wish to initialize
	@return CRYPT_OK if successful
*/
int md5_init(hash_state * md)
{
	LFH_ARGCHK(md != NULL);
	md->md5.state[0] = 0x67452301UL;
	md->md5.state[1] = 0xefcdab89UL;
	md->md5.state[2] = 0x98badcfeUL;
	md->md5.state[3] = 0x10325476UL;
	md->md5.curlen = 0;
	md->md5.length = 0;
	return CRYPT_OK;
}

/**
	Process a block of memory though the hash
	@param md     The hash state
	@param in     The data to hash
	@param inlen  The length of the data (octets)
	@return CRYPT_OK if successful
*/
HASH_PROCESS(md5_process, s_md5_compress, md5, 64)

/**
	Terminate the hash to get the digest
	@param md  The hash state
	@param out [out] The destination of the hash (16 bytes)
	@return CRYPT_OK if successful
*/
int md5_done(hash_state * md, unsigned char *out)
{
	int i;

	LFH_ARGCHK(md  != NULL);
	LFH_ARGCHK(out != NULL);

	if (md->md5.curlen >= sizeof(md->md5.buf)) {
		return CRYPT_INVALID_ARG;
	}

	md->md5.length += md->md5.curlen * 8;

	md->md5.buf[md->md5.curlen++] = (unsigned char)0x80;

	/* if the length is currently above 56 bytes we append zeros
	 * then compress.  Then we can fall back to padding zeros and length
	 * encoding like normal.
	 */
	if (md->md5.curlen > 56) {
		while (md->md5.curlen < 64) {
			md->md5.buf[md->md5.curlen++] = (unsigned char)0;
		}
		s_md5_compress(md, md->md5.buf);
		md->md5.curlen = 0;
	}

	while (md->md5.curlen < 56) {
		md->md5.buf[md->md5.curlen++] = (unsigned char)0;
	}

	STORE64L(md->md5.length, md->md5.buf+56);
	s_md5_compress(md, md->md5.buf);

	for (i = 0; i < 4; i++) {
		STORE32L(md->md5.state[i], out+(4*i));
	}
#ifdef LFH_CLEAN_STACK
	zeromem(md, sizeof(hash_state));
#endif
	return CRYPT_OK;
}

/**
	Self-test the hash
	@return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int  md5_test(void)
{
 #ifndef LFH_TEST
	return CRYPT_NOP;
 #else
	static const struct {
		const char *msg;
		unsigned char hash[16];
	} tests[] = {
	{ "",
		{ 0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
		0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e } },
	{ "a",
		{0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8,
		0x31, 0xc3, 0x99, 0xe2, 0x69, 0x77, 0x26, 0x61 } },
	{ "abc",
		{ 0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
		0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72 } },
	{ "message digest",
		{ 0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d,
		0x52, 0x5a, 0x2f, 0x31, 0xaa, 0xf1, 0x61, 0xd0 } },
	{ "abcdefghijklmnopqrstuvwxyz",
		{ 0xc3, 0xfc, 0xd3, 0xd7, 0x61, 0x92, 0xe4, 0x00,
		0x7d, 0xfb, 0x49, 0x6c, 0xca, 0x67, 0xe1, 0x3b } },
	{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		{ 0xd1, 0x74, 0xab, 0x98, 0xd2, 0x77, 0xd9, 0xf5,
		0xa5, 0x61, 0x1c, 0x2c, 0x9f, 0x41, 0x9d, 0x9f } },
	{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
		{ 0x57, 0xed, 0xf4, 0xa2, 0x2b, 0xe3, 0xc9, 0x55,
		0xac, 0x49, 0xda, 0x2e, 0x21, 0x07, 0xb6, 0x7a } },
	{ NULL, { 0 } }
	};

	int i;
	unsigned char tmp[16];
	hash_state md;

	for (i = 0; tests[i].msg != NULL; i++) {
		md5_init(&md);
		md5_process(&md, (unsigned char *)tests[i].msg, (unsigned long)XSTRLEN(tests[i].msg));
		md5_done(&md, tmp);
		if (compare_testvector(tmp, sizeof(tmp), tests[i].hash, sizeof(tests[i].hash), "MD5", i)) {
		 return CRYPT_FAIL_TESTVECTOR;
		}
	}
	return CRYPT_OK;
 #endif
}

#endif

/**
	@file sha1.c
	LFH_SHA1 code by Tom St Denis
*/

#ifdef LFH_SHA1

const struct lfh_hash_descriptor sha1_desc =
{
	"sha1",
	2,
	20,
	64,

	{ 1, 3, 14, 3, 2, 26,  },
	6,

	&sha1_init,
	&sha1_process,
	&sha1_done,
	&sha1_test,
	NULL
};

#define sha1_F0(x,y,z)  (z ^ (x & (y ^ z)))
#define sha1_F1(x,y,z)  (x ^ y ^ z)
#define sha1_F2(x,y,z)  ((x & y) | (z & (x | y)))
#define sha1_F3(x,y,z)  (x ^ y ^ z)

#ifdef LFH_CLEAN_STACK
static int ss_sha1_compress(hash_state *md, const unsigned char *buf)
#else
static int  s_sha1_compress(hash_state *md, const unsigned char *buf)
#endif
{
	ulong32 a,b,c,d,e,W[80],i;
#ifdef LFH_SMALL_CODE
	ulong32 t;
#endif

	for (i = 0; i < 16; i++) {
		LOAD32H(W[i], buf + (4*i));
	}

	a = md->sha1.state[0];
	b = md->sha1.state[1];
	c = md->sha1.state[2];
	d = md->sha1.state[3];
	e = md->sha1.state[4];

	for (i = 16; i < 80; i++) {
		W[i] = ROL(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);
	}

	#define sha1_FF0(a,b,c,d,e,i) e = (ROLc(a, 5) + sha1_F0(b,c,d) + e + W[i] + 0x5a827999UL); b = ROLc(b, 30);
	#define sha1_FF1(a,b,c,d,e,i) e = (ROLc(a, 5) + sha1_F1(b,c,d) + e + W[i] + 0x6ed9eba1UL); b = ROLc(b, 30);
	#define sha1_FF2(a,b,c,d,e,i) e = (ROLc(a, 5) + sha1_F2(b,c,d) + e + W[i] + 0x8f1bbcdcUL); b = ROLc(b, 30);
	#define sha1_FF3(a,b,c,d,e,i) e = (ROLc(a, 5) + sha1_F3(b,c,d) + e + W[i] + 0xca62c1d6UL); b = ROLc(b, 30);

#ifdef LFH_SMALL_CODE

	for (i = 0; i < 20; ) {
		sha1_FF0(a,b,c,d,e,i++); t = e; e = d; d = c; c = b; b = a; a = t;
	}

	for (; i < 40; ) {
		sha1_FF1(a,b,c,d,e,i++); t = e; e = d; d = c; c = b; b = a; a = t;
	}

	for (; i < 60; ) {
		sha1_FF2(a,b,c,d,e,i++); t = e; e = d; d = c; c = b; b = a; a = t;
	}

	for (; i < 80; ) {
		sha1_FF3(a,b,c,d,e,i++); t = e; e = d; d = c; c = b; b = a; a = t;
	}

#else

	for (i = 0; i < 20; ) {
		sha1_FF0(a,b,c,d,e,i++);
		sha1_FF0(e,a,b,c,d,i++);
		sha1_FF0(d,e,a,b,c,i++);
		sha1_FF0(c,d,e,a,b,i++);
		sha1_FF0(b,c,d,e,a,i++);
	}

	for (; i < 40; )  {
		sha1_FF1(a,b,c,d,e,i++);
		sha1_FF1(e,a,b,c,d,i++);
		sha1_FF1(d,e,a,b,c,i++);
		sha1_FF1(c,d,e,a,b,i++);
		sha1_FF1(b,c,d,e,a,i++);
	}

	for (; i < 60; )  {
		sha1_FF2(a,b,c,d,e,i++);
		sha1_FF2(e,a,b,c,d,i++);
		sha1_FF2(d,e,a,b,c,i++);
		sha1_FF2(c,d,e,a,b,i++);
		sha1_FF2(b,c,d,e,a,i++);
	}

	for (; i < 80; )  {
		sha1_FF3(a,b,c,d,e,i++);
		sha1_FF3(e,a,b,c,d,i++);
		sha1_FF3(d,e,a,b,c,i++);
		sha1_FF3(c,d,e,a,b,i++);
		sha1_FF3(b,c,d,e,a,i++);
	}
#endif

	#undef sha1_FF0
	#undef sha1_FF1
	#undef sha1_FF2
	#undef sha1_FF3

	md->sha1.state[0] = md->sha1.state[0] + a;
	md->sha1.state[1] = md->sha1.state[1] + b;
	md->sha1.state[2] = md->sha1.state[2] + c;
	md->sha1.state[3] = md->sha1.state[3] + d;
	md->sha1.state[4] = md->sha1.state[4] + e;

	return CRYPT_OK;
}

#ifdef LFH_CLEAN_STACK
static int s_sha1_compress(hash_state *md, const unsigned char *buf)
{
	int err;
	err = ss_sha1_compress(md, buf);
	burn_stack(sizeof(ulong32) * 87);
	return err;
}
#endif

/**
	Initialize the hash state
	@param md   The hash state you wish to initialize
	@return CRYPT_OK if successful
*/
int sha1_init(hash_state * md)
{
	LFH_ARGCHK(md != NULL);
	md->sha1.state[0] = 0x67452301UL;
	md->sha1.state[1] = 0xefcdab89UL;
	md->sha1.state[2] = 0x98badcfeUL;
	md->sha1.state[3] = 0x10325476UL;
	md->sha1.state[4] = 0xc3d2e1f0UL;
	md->sha1.curlen = 0;
	md->sha1.length = 0;
	return CRYPT_OK;
}

/**
	Process a block of memory though the hash
	@param md     The hash state
	@param in     The data to hash
	@param inlen  The length of the data (octets)
	@return CRYPT_OK if successful
*/
HASH_PROCESS(sha1_process, s_sha1_compress, sha1, 64)

/**
	Terminate the hash to get the digest
	@param md  The hash state
	@param out [out] The destination of the hash (20 bytes)
	@return CRYPT_OK if successful
*/
int sha1_done(hash_state * md, unsigned char *out)
{
	int i;

	LFH_ARGCHK(md  != NULL);
	LFH_ARGCHK(out != NULL);

	if (md->sha1.curlen >= sizeof(md->sha1.buf)) {
		return CRYPT_INVALID_ARG;
	}

	md->sha1.length += md->sha1.curlen * 8;

	md->sha1.buf[md->sha1.curlen++] = (unsigned char)0x80;

	/* if the length is currently above 56 bytes we append zeros
	 * then compress.  Then we can fall back to padding zeros and length
	 * encoding like normal.
	 */
	if (md->sha1.curlen > 56) {
		while (md->sha1.curlen < 64) {
			md->sha1.buf[md->sha1.curlen++] = (unsigned char)0;
		}
		s_sha1_compress(md, md->sha1.buf);
		md->sha1.curlen = 0;
	}

	while (md->sha1.curlen < 56) {
		md->sha1.buf[md->sha1.curlen++] = (unsigned char)0;
	}

	STORE64H(md->sha1.length, md->sha1.buf+56);
	s_sha1_compress(md, md->sha1.buf);

	for (i = 0; i < 5; i++) {
		STORE32H(md->sha1.state[i], out+(4*i));
	}
#ifdef LFH_CLEAN_STACK
	zeromem(md, sizeof(hash_state));
#endif
	return CRYPT_OK;
}

/**
	Self-test the hash
	@return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int  sha1_test(void)
{
 #ifndef LFH_TEST
	return CRYPT_NOP;
 #else
	static const struct {
		const char *msg;
		unsigned char hash[20];
	} tests[] = {
	{ "abc",
		{ 0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
		0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
		0x9c, 0xd0, 0xd8, 0x9d }
	},
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		{ 0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E,
		0xBA, 0xAE, 0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5,
		0xE5, 0x46, 0x70, 0xF1 }
	}
	};

	int i;
	unsigned char tmp[20];
	hash_state md;

	for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0]));  i++) {
		sha1_init(&md);
		sha1_process(&md, (unsigned char*)tests[i].msg, (unsigned long)XSTRLEN(tests[i].msg));
		sha1_done(&md, tmp);
		if (compare_testvector(tmp, sizeof(tmp), tests[i].hash, sizeof(tests[i].hash), "SHA1", i)) {
		 return CRYPT_FAIL_TESTVECTOR;
		}
	}
	return CRYPT_OK;
	#endif
}

#endif

/**
	@param sha224.c
	LFH_SHA-224 new NIST standard based off of LFH_SHA-256 truncated to 224 bits (Tom St Denis)
*/

#if defined(LFH_SHA224) && defined(LFH_SHA256)

const struct lfh_hash_descriptor sha224_desc =
{
	"sha224",
	10,
	28,
	64,

	{ 2, 16, 840, 1, 101, 3, 4, 2, 4,  },
	9,

	&sha224_init,
	&sha256_process,
	&sha224_done,
	&sha224_test,
	NULL
};

/**
	Initialize the hash state
	@param md   The hash state you wish to initialize
	@return CRYPT_OK if successful
*/
int sha224_init(hash_state * md)
{
	LFH_ARGCHK(md != NULL);

	md->sha256.curlen = 0;
	md->sha256.length = 0;
	md->sha256.state[0] = 0xc1059ed8UL;
	md->sha256.state[1] = 0x367cd507UL;
	md->sha256.state[2] = 0x3070dd17UL;
	md->sha256.state[3] = 0xf70e5939UL;
	md->sha256.state[4] = 0xffc00b31UL;
	md->sha256.state[5] = 0x68581511UL;
	md->sha256.state[6] = 0x64f98fa7UL;
	md->sha256.state[7] = 0xbefa4fa4UL;
	return CRYPT_OK;
}

/**
	Terminate the hash to get the digest
	@param md  The hash state
	@param out [out] The destination of the hash (28 bytes)
	@return CRYPT_OK if successful
*/
int sha224_done(hash_state * md, unsigned char *out)
{
	unsigned char buf[32];
	int err;

	LFH_ARGCHK(md  != NULL);
	LFH_ARGCHK(out != NULL);

	err = sha256_done(md, buf);
	XMEMCPY(out, buf, 28);
#ifdef LFH_CLEAN_STACK
	zeromem(buf, sizeof(buf));
#endif
	return err;
}

/**
	Self-test the hash
	@return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int  sha224_test(void)
{
 #ifndef LFH_TEST
	return CRYPT_NOP;
 #else
	static const struct {
		const char *msg;
		unsigned char hash[28];
	} tests[] = {
	{ "abc",
		{ 0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8,
		0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2,
		0x55, 0xb3, 0x2a, 0xad, 0xbc, 0xe4, 0xbd,
		0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7 }
	},
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		{ 0x75, 0x38, 0x8b, 0x16, 0x51, 0x27, 0x76,
		0xcc, 0x5d, 0xba, 0x5d, 0xa1, 0xfd, 0x89,
		0x01, 0x50, 0xb0, 0xc6, 0x45, 0x5c, 0xb4,
		0xf5, 0x8b, 0x19, 0x52, 0x52, 0x25, 0x25 }
	},
	};

	int i;
	unsigned char tmp[28];
	hash_state md;

	for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); i++) {
		sha224_init(&md);
		sha224_process(&md, (unsigned char*)tests[i].msg, (unsigned long)XSTRLEN(tests[i].msg));
		sha224_done(&md, tmp);
		if (compare_testvector(tmp, sizeof(tmp), tests[i].hash, sizeof(tests[i].hash), "SHA224", i)) {
		 return CRYPT_FAIL_TESTVECTOR;
		}
	}
	return CRYPT_OK;
 #endif
}

#endif /* defined(LFH_SHA224) && defined(LFH_SHA256) */

/**
	@file sha256.c
	LFH_SHA256 by Tom St Denis
*/

#ifdef LFH_SHA256

const struct lfh_hash_descriptor sha256_desc =
{
	"sha256",
	0,
	32,
	64,

	{ 2, 16, 840, 1, 101, 3, 4, 2, 1,  },
	9,

	&sha256_init,
	&sha256_process,
	&sha256_done,
	&sha256_test,
	NULL
};

#ifdef LFH_SMALL_CODE
static const ulong32 K[64] = {
	0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL,
	0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL,
	0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL,
	0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
	0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL, 0x983e5152UL,
	0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
	0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL,
	0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
	0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL,
	0xd6990624UL, 0xf40e3585UL, 0x106aa070UL, 0x19a4c116UL, 0x1e376c08UL,
	0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL,
	0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
	0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};
#endif

#define sha256_Ch(x,y,z)       (z ^ (x & (y ^ z)))
#define sha256_Maj(x,y,z)      (((x | y) & z) | (x & y))
#define sha256_S(x, n)         RORc((x),(n))
#define sha256_R(x, n)         (((x)&0xFFFFFFFFUL)>>(n))
#define sha256_Sigma0(x)       (sha256_S(x, 2) ^ sha256_S(x, 13) ^ sha256_S(x, 22))
#define sha256_Sigma1(x)       (sha256_S(x, 6) ^ sha256_S(x, 11) ^ sha256_S(x, 25))
#define sha256_Gamma0(x)       (sha256_S(x, 7) ^ sha256_S(x, 18) ^ sha256_R(x, 3))
#define sha256_Gamma1(x)       (sha256_S(x, 17) ^ sha256_S(x, 19) ^ sha256_R(x, 10))

#ifdef LFH_CLEAN_STACK
static int ss_sha256_compress(hash_state * md, const unsigned char *buf)
#else
static int s_sha256_compress(hash_state * md, const unsigned char *buf)
#endif
{
	ulong32 sha256_S[8], W[64], t0, t1;
#ifdef LFH_SMALL_CODE
	ulong32 t;
#endif
	int i;

	for (i = 0; i < 8; i++) {
		sha256_S[i] = md->sha256.state[i];
	}

	for (i = 0; i < 16; i++) {
		LOAD32H(W[i], buf + (4*i));
	}

	for (i = 16; i < 64; i++) {
		W[i] = sha256_Gamma1(W[i - 2]) + W[i - 7] + sha256_Gamma0(W[i - 15]) + W[i - 16];
	}

#ifdef LFH_SMALL_CODE
#define RND(a,b,c,d,e,f,g,h,i) \
	 t0 = h + sha256_Sigma1(e) + sha256_Ch(e, f, g) + K[i] + W[i]; \
	 t1 = sha256_Sigma0(a) + sha256_Maj(a, b, c); \
	 d += t0; \
	 h  = t0 + t1;

	 for (i = 0; i < 64; ++i) {
		 RND(sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],i);
		 t = sha256_S[7]; sha256_S[7] = sha256_S[6]; sha256_S[6] = sha256_S[5]; sha256_S[5] = sha256_S[4];
		 sha256_S[4] = sha256_S[3]; sha256_S[3] = sha256_S[2]; sha256_S[2] = sha256_S[1]; sha256_S[1] = sha256_S[0]; sha256_S[0] = t;
	 }
#else
#define RND(a,b,c,d,e,f,g,h,i,ki) \
	 t0 = h + sha256_Sigma1(e) + sha256_Ch(e, f, g) + ki + W[i]; \
	 t1 = sha256_Sigma0(a) + sha256_Maj(a, b, c); \
	 d += t0; \
	 h  = t0 + t1;

	RND(sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],0,0x428a2f98);
	RND(sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],1,0x71374491);
	RND(sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],2,0xb5c0fbcf);
	RND(sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],3,0xe9b5dba5);
	RND(sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],4,0x3956c25b);
	RND(sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],5,0x59f111f1);
	RND(sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],6,0x923f82a4);
	RND(sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],7,0xab1c5ed5);
	RND(sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],8,0xd807aa98);
	RND(sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],9,0x12835b01);
	RND(sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],10,0x243185be);
	RND(sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],11,0x550c7dc3);
	RND(sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],12,0x72be5d74);
	RND(sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],13,0x80deb1fe);
	RND(sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],14,0x9bdc06a7);
	RND(sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],15,0xc19bf174);
	RND(sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],16,0xe49b69c1);
	RND(sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],17,0xefbe4786);
	RND(sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],18,0x0fc19dc6);
	RND(sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],19,0x240ca1cc);
	RND(sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],20,0x2de92c6f);
	RND(sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],21,0x4a7484aa);
	RND(sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],22,0x5cb0a9dc);
	RND(sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],23,0x76f988da);
	RND(sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],24,0x983e5152);
	RND(sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],25,0xa831c66d);
	RND(sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],26,0xb00327c8);
	RND(sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],27,0xbf597fc7);
	RND(sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],28,0xc6e00bf3);
	RND(sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],29,0xd5a79147);
	RND(sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],30,0x06ca6351);
	RND(sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],31,0x14292967);
	RND(sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],32,0x27b70a85);
	RND(sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],33,0x2e1b2138);
	RND(sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],34,0x4d2c6dfc);
	RND(sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],35,0x53380d13);
	RND(sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],36,0x650a7354);
	RND(sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],37,0x766a0abb);
	RND(sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],38,0x81c2c92e);
	RND(sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],39,0x92722c85);
	RND(sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],40,0xa2bfe8a1);
	RND(sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],41,0xa81a664b);
	RND(sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],42,0xc24b8b70);
	RND(sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],43,0xc76c51a3);
	RND(sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],44,0xd192e819);
	RND(sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],45,0xd6990624);
	RND(sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],46,0xf40e3585);
	RND(sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],47,0x106aa070);
	RND(sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],48,0x19a4c116);
	RND(sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],49,0x1e376c08);
	RND(sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],50,0x2748774c);
	RND(sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],51,0x34b0bcb5);
	RND(sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],52,0x391c0cb3);
	RND(sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],53,0x4ed8aa4a);
	RND(sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],54,0x5b9cca4f);
	RND(sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],55,0x682e6ff3);
	RND(sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],56,0x748f82ee);
	RND(sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],57,0x78a5636f);
	RND(sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],58,0x84c87814);
	RND(sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],59,0x8cc70208);
	RND(sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],sha256_S[3],60,0x90befffa);
	RND(sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],sha256_S[2],61,0xa4506ceb);
	RND(sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],sha256_S[1],62,0xbef9a3f7);
	RND(sha256_S[1],sha256_S[2],sha256_S[3],sha256_S[4],sha256_S[5],sha256_S[6],sha256_S[7],sha256_S[0],63,0xc67178f2);
#endif
#undef RND

	for (i = 0; i < 8; i++) {
		md->sha256.state[i] = md->sha256.state[i] + sha256_S[i];
	}
	return CRYPT_OK;
}

#ifdef LFH_CLEAN_STACK
static int s_sha256_compress(hash_state * md, const unsigned char *buf)
{
	int err;
	err = ss_sha256_compress(md, buf);
	burn_stack(sizeof(ulong32) * 74);
	return err;
}
#endif

/**
	Initialize the hash state
	@param md   The hash state you wish to initialize
	@return CRYPT_OK if successful
*/
int sha256_init(hash_state * md)
{
	LFH_ARGCHK(md != NULL);

	md->sha256.curlen = 0;
	md->sha256.length = 0;
	md->sha256.state[0] = 0x6A09E667UL;
	md->sha256.state[1] = 0xBB67AE85UL;
	md->sha256.state[2] = 0x3C6EF372UL;
	md->sha256.state[3] = 0xA54FF53AUL;
	md->sha256.state[4] = 0x510E527FUL;
	md->sha256.state[5] = 0x9B05688CUL;
	md->sha256.state[6] = 0x1F83D9ABUL;
	md->sha256.state[7] = 0x5BE0CD19UL;
	return CRYPT_OK;
}

/**
	Process a block of memory though the hash
	@param md     The hash state
	@param in     The data to hash
	@param inlen  The length of the data (octets)
	@return CRYPT_OK if successful
*/
HASH_PROCESS(sha256_process,s_sha256_compress, sha256, 64)

/**
	Terminate the hash to get the digest
	@param md  The hash state
	@param out [out] The destination of the hash (32 bytes)
	@return CRYPT_OK if successful
*/
int sha256_done(hash_state * md, unsigned char *out)
{
	int i;

	LFH_ARGCHK(md  != NULL);
	LFH_ARGCHK(out != NULL);

	if (md->sha256.curlen >= sizeof(md->sha256.buf)) {
		return CRYPT_INVALID_ARG;
	}

	md->sha256.length += md->sha256.curlen * 8;

	md->sha256.buf[md->sha256.curlen++] = (unsigned char)0x80;

	/* if the length is currently above 56 bytes we append zeros
	 * then compress.  Then we can fall back to padding zeros and length
	 * encoding like normal.
	 */
	if (md->sha256.curlen > 56) {
		while (md->sha256.curlen < 64) {
			md->sha256.buf[md->sha256.curlen++] = (unsigned char)0;
		}
		s_sha256_compress(md, md->sha256.buf);
		md->sha256.curlen = 0;
	}

	while (md->sha256.curlen < 56) {
		md->sha256.buf[md->sha256.curlen++] = (unsigned char)0;
	}

	STORE64H(md->sha256.length, md->sha256.buf+56);
	s_sha256_compress(md, md->sha256.buf);

	for (i = 0; i < 8; i++) {
		STORE32H(md->sha256.state[i], out+(4*i));
	}
#ifdef LFH_CLEAN_STACK
	zeromem(md, sizeof(hash_state));
#endif
	return CRYPT_OK;
}

/**
	Self-test the hash
	@return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int  sha256_test(void)
{
 #ifndef LFH_TEST
	return CRYPT_NOP;
 #else
	static const struct {
		const char *msg;
		unsigned char hash[32];
	} tests[] = {
	{ "abc",
		{ 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad }
	},
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		{ 0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
		0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
		0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
		0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1 }
	},
	};

	int i;
	unsigned char tmp[32];
	hash_state md;

	for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); i++) {
		sha256_init(&md);
		sha256_process(&md, (unsigned char*)tests[i].msg, (unsigned long)XSTRLEN(tests[i].msg));
		sha256_done(&md, tmp);
		if (compare_testvector(tmp, sizeof(tmp), tests[i].hash, sizeof(tests[i].hash), "SHA256", i)) {
		 return CRYPT_FAIL_TESTVECTOR;
		}
	}
	return CRYPT_OK;
 #endif
}

#endif

/**
	@param sha384.c
	LFH_SHA384 hash included in sha512.c, Tom St Denis
*/

#if defined(LFH_SHA384) && defined(LFH_SHA512)

const struct lfh_hash_descriptor sha384_desc =
{
	"sha384",
	4,
	48,
	128,

	{ 2, 16, 840, 1, 101, 3, 4, 2, 2,  },
	9,

	&sha384_init,
	&sha512_process,
	&sha384_done,
	&sha384_test,
	NULL
};

/**
	Initialize the hash state
	@param md   The hash state you wish to initialize
	@return CRYPT_OK if successful
*/
int sha384_init(hash_state * md)
{
	LFH_ARGCHK(md != NULL);

	md->sha512.curlen = 0;
	md->sha512.length = 0;
	md->sha512.state[0] = CONST64(0xcbbb9d5dc1059ed8);
	md->sha512.state[1] = CONST64(0x629a292a367cd507);
	md->sha512.state[2] = CONST64(0x9159015a3070dd17);
	md->sha512.state[3] = CONST64(0x152fecd8f70e5939);
	md->sha512.state[4] = CONST64(0x67332667ffc00b31);
	md->sha512.state[5] = CONST64(0x8eb44a8768581511);
	md->sha512.state[6] = CONST64(0xdb0c2e0d64f98fa7);
	md->sha512.state[7] = CONST64(0x47b5481dbefa4fa4);
	return CRYPT_OK;
}

/**
	Terminate the hash to get the digest
	@param md  The hash state
	@param out [out] The destination of the hash (48 bytes)
	@return CRYPT_OK if successful
*/
int sha384_done(hash_state * md, unsigned char *out)
{
	unsigned char buf[64];

	LFH_ARGCHK(md  != NULL);
	LFH_ARGCHK(out != NULL);

	if (md->sha512.curlen >= sizeof(md->sha512.buf)) {
		return CRYPT_INVALID_ARG;
	}

	sha512_done(md, buf);
	XMEMCPY(out, buf, 48);
#ifdef LFH_CLEAN_STACK
	zeromem(buf, sizeof(buf));
#endif
	return CRYPT_OK;
}

/**
	Self-test the hash
	@return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int  sha384_test(void)
{
 #ifndef LFH_TEST
	return CRYPT_NOP;
 #else
	static const struct {
		const char *msg;
		unsigned char hash[48];
	} tests[] = {
	{ "abc",
		{ 0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b,
		0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
		0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
		0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
		0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23,
		0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7 }
	},
	{ "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		{ 0x09, 0x33, 0x0c, 0x33, 0xf7, 0x11, 0x47, 0xe8,
		0x3d, 0x19, 0x2f, 0xc7, 0x82, 0xcd, 0x1b, 0x47,
		0x53, 0x11, 0x1b, 0x17, 0x3b, 0x3b, 0x05, 0xd2,
		0x2f, 0xa0, 0x80, 0x86, 0xe3, 0xb0, 0xf7, 0x12,
		0xfc, 0xc7, 0xc7, 0x1a, 0x55, 0x7e, 0x2d, 0xb9,
		0x66, 0xc3, 0xe9, 0xfa, 0x91, 0x74, 0x60, 0x39 }
	},
	};

	int i;
	unsigned char tmp[48];
	hash_state md;

	for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); i++) {
		sha384_init(&md);
		sha384_process(&md, (unsigned char*)tests[i].msg, (unsigned long)XSTRLEN(tests[i].msg));
		sha384_done(&md, tmp);
		if (compare_testvector(tmp, sizeof(tmp), tests[i].hash, sizeof(tests[i].hash), "SHA384", i)) {
		 return CRYPT_FAIL_TESTVECTOR;
		}
	}
	return CRYPT_OK;
 #endif
}

#endif /* defined(LFH_SHA384) && defined(LFH_SHA512) */

/**
	@param sha512.c
	LFH_SHA512 by Tom St Denis
*/

#ifdef LFH_SHA512

const struct lfh_hash_descriptor sha512_desc =
{
	"sha512",
	5,
	64,
	128,

	{ 2, 16, 840, 1, 101, 3, 4, 2, 3,  },
	9,

	&sha512_init,
	&sha512_process,
	&sha512_done,
	&sha512_test,
	NULL
};

static const ulong64 K[80] = {
CONST64(0x428a2f98d728ae22), CONST64(0x7137449123ef65cd),
CONST64(0xb5c0fbcfec4d3b2f), CONST64(0xe9b5dba58189dbbc),
CONST64(0x3956c25bf348b538), CONST64(0x59f111f1b605d019),
CONST64(0x923f82a4af194f9b), CONST64(0xab1c5ed5da6d8118),
CONST64(0xd807aa98a3030242), CONST64(0x12835b0145706fbe),
CONST64(0x243185be4ee4b28c), CONST64(0x550c7dc3d5ffb4e2),
CONST64(0x72be5d74f27b896f), CONST64(0x80deb1fe3b1696b1),
CONST64(0x9bdc06a725c71235), CONST64(0xc19bf174cf692694),
CONST64(0xe49b69c19ef14ad2), CONST64(0xefbe4786384f25e3),
CONST64(0x0fc19dc68b8cd5b5), CONST64(0x240ca1cc77ac9c65),
CONST64(0x2de92c6f592b0275), CONST64(0x4a7484aa6ea6e483),
CONST64(0x5cb0a9dcbd41fbd4), CONST64(0x76f988da831153b5),
CONST64(0x983e5152ee66dfab), CONST64(0xa831c66d2db43210),
CONST64(0xb00327c898fb213f), CONST64(0xbf597fc7beef0ee4),
CONST64(0xc6e00bf33da88fc2), CONST64(0xd5a79147930aa725),
CONST64(0x06ca6351e003826f), CONST64(0x142929670a0e6e70),
CONST64(0x27b70a8546d22ffc), CONST64(0x2e1b21385c26c926),
CONST64(0x4d2c6dfc5ac42aed), CONST64(0x53380d139d95b3df),
CONST64(0x650a73548baf63de), CONST64(0x766a0abb3c77b2a8),
CONST64(0x81c2c92e47edaee6), CONST64(0x92722c851482353b),
CONST64(0xa2bfe8a14cf10364), CONST64(0xa81a664bbc423001),
CONST64(0xc24b8b70d0f89791), CONST64(0xc76c51a30654be30),
CONST64(0xd192e819d6ef5218), CONST64(0xd69906245565a910),
CONST64(0xf40e35855771202a), CONST64(0x106aa07032bbd1b8),
CONST64(0x19a4c116b8d2d0c8), CONST64(0x1e376c085141ab53),
CONST64(0x2748774cdf8eeb99), CONST64(0x34b0bcb5e19b48a8),
CONST64(0x391c0cb3c5c95a63), CONST64(0x4ed8aa4ae3418acb),
CONST64(0x5b9cca4f7763e373), CONST64(0x682e6ff3d6b2b8a3),
CONST64(0x748f82ee5defb2fc), CONST64(0x78a5636f43172f60),
CONST64(0x84c87814a1f0ab72), CONST64(0x8cc702081a6439ec),
CONST64(0x90befffa23631e28), CONST64(0xa4506cebde82bde9),
CONST64(0xbef9a3f7b2c67915), CONST64(0xc67178f2e372532b),
CONST64(0xca273eceea26619c), CONST64(0xd186b8c721c0c207),
CONST64(0xeada7dd6cde0eb1e), CONST64(0xf57d4f7fee6ed178),
CONST64(0x06f067aa72176fba), CONST64(0x0a637dc5a2c898a6),
CONST64(0x113f9804bef90dae), CONST64(0x1b710b35131c471b),
CONST64(0x28db77f523047d84), CONST64(0x32caab7b40c72493),
CONST64(0x3c9ebe0a15c9bebc), CONST64(0x431d67c49c100d4c),
CONST64(0x4cc5d4becb3e42b6), CONST64(0x597f299cfc657e2a),
CONST64(0x5fcb6fab3ad6faec), CONST64(0x6c44198c4a475817)
};

#define sha512_Ch(x,y,z)       (z ^ (x & (y ^ z)))
#define sha512_Maj(x,y,z)      (((x | y) & z) | (x & y))
#define sha512_S(x, n)         ROR64c(x, n)
#define sha512_R(x, n)         (((x)&CONST64(0xFFFFFFFFFFFFFFFF))>>((ulong64)n))
#define sha512_Sigma0(x)       (sha512_S(x, 28) ^ sha512_S(x, 34) ^ sha512_S(x, 39))
#define sha512_Sigma1(x)       (sha512_S(x, 14) ^ sha512_S(x, 18) ^ sha512_S(x, 41))
#define sha512_Gamma0(x)       (sha512_S(x, 1) ^ sha512_S(x, 8) ^ sha512_R(x, 7))
#define sha512_Gamma1(x)       (sha512_S(x, 19) ^ sha512_S(x, 61) ^ sha512_R(x, 6))

#ifdef LFH_CLEAN_STACK
static int ss_sha512_compress(hash_state * md, const unsigned char *buf)
#else
static int  s_sha512_compress(hash_state * md, const unsigned char *buf)
#endif
{
	ulong64 sha512_S[8], W[80], t0, t1;
	int i;

	for (i = 0; i < 8; i++) {
		sha512_S[i] = md->sha512.state[i];
	}

	for (i = 0; i < 16; i++) {
		LOAD64H(W[i], buf + (8*i));
	}

	for (i = 16; i < 80; i++) {
		W[i] = sha512_Gamma1(W[i - 2]) + W[i - 7] + sha512_Gamma0(W[i - 15]) + W[i - 16];
	}

#ifdef LFH_SMALL_CODE
	for (i = 0; i < 80; i++) {
		t0 = sha512_S[7] + sha512_Sigma1(sha512_S[4]) + sha512_Ch(sha512_S[4], sha512_S[5], sha512_S[6]) + K[i] + W[i];
		t1 = sha512_Sigma0(sha512_S[0]) + sha512_Maj(sha512_S[0], sha512_S[1], sha512_S[2]);
		sha512_S[7] = sha512_S[6];
		sha512_S[6] = sha512_S[5];
		sha512_S[5] = sha512_S[4];
		sha512_S[4] = sha512_S[3] + t0;
		sha512_S[3] = sha512_S[2];
		sha512_S[2] = sha512_S[1];
		sha512_S[1] = sha512_S[0];
		sha512_S[0] = t0 + t1;
	}
#else
#define RND(a,b,c,d,e,f,g,h,i) \
	 t0 = h + sha512_Sigma1(e) + sha512_Ch(e, f, g) + K[i] + W[i]; \
	 t1 = sha512_Sigma0(a) + sha512_Maj(a, b, c); \
	 d += t0; \
	 h  = t0 + t1;

	for (i = 0; i < 80; i += 8) {
		RND(sha512_S[0],sha512_S[1],sha512_S[2],sha512_S[3],sha512_S[4],sha512_S[5],sha512_S[6],sha512_S[7],i+0);
		RND(sha512_S[7],sha512_S[0],sha512_S[1],sha512_S[2],sha512_S[3],sha512_S[4],sha512_S[5],sha512_S[6],i+1);
		RND(sha512_S[6],sha512_S[7],sha512_S[0],sha512_S[1],sha512_S[2],sha512_S[3],sha512_S[4],sha512_S[5],i+2);
		RND(sha512_S[5],sha512_S[6],sha512_S[7],sha512_S[0],sha512_S[1],sha512_S[2],sha512_S[3],sha512_S[4],i+3);
		RND(sha512_S[4],sha512_S[5],sha512_S[6],sha512_S[7],sha512_S[0],sha512_S[1],sha512_S[2],sha512_S[3],i+4);
		RND(sha512_S[3],sha512_S[4],sha512_S[5],sha512_S[6],sha512_S[7],sha512_S[0],sha512_S[1],sha512_S[2],i+5);
		RND(sha512_S[2],sha512_S[3],sha512_S[4],sha512_S[5],sha512_S[6],sha512_S[7],sha512_S[0],sha512_S[1],i+6);
		RND(sha512_S[1],sha512_S[2],sha512_S[3],sha512_S[4],sha512_S[5],sha512_S[6],sha512_S[7],sha512_S[0],i+7);
	}
#endif

	for (i = 0; i < 8; i++) {
		md->sha512.state[i] = md->sha512.state[i] + sha512_S[i];
	}

	return CRYPT_OK;
}

#ifdef LFH_CLEAN_STACK
static int s_sha512_compress(hash_state * md, const unsigned char *buf)
{
	int err;
	err = ss_sha512_compress(md, buf);
	burn_stack(sizeof(ulong64) * 90 + sizeof(int));
	return err;
}
#endif

/**
	Initialize the hash state
	@param md   The hash state you wish to initialize
	@return CRYPT_OK if successful
*/
int sha512_init(hash_state * md)
{
	LFH_ARGCHK(md != NULL);
	md->sha512.curlen = 0;
	md->sha512.length = 0;
	md->sha512.state[0] = CONST64(0x6a09e667f3bcc908);
	md->sha512.state[1] = CONST64(0xbb67ae8584caa73b);
	md->sha512.state[2] = CONST64(0x3c6ef372fe94f82b);
	md->sha512.state[3] = CONST64(0xa54ff53a5f1d36f1);
	md->sha512.state[4] = CONST64(0x510e527fade682d1);
	md->sha512.state[5] = CONST64(0x9b05688c2b3e6c1f);
	md->sha512.state[6] = CONST64(0x1f83d9abfb41bd6b);
	md->sha512.state[7] = CONST64(0x5be0cd19137e2179);
	return CRYPT_OK;
}

/**
	Process a block of memory though the hash
	@param md     The hash state
	@param in     The data to hash
	@param inlen  The length of the data (octets)
	@return CRYPT_OK if successful
*/
HASH_PROCESS(sha512_process, s_sha512_compress, sha512, 128)

/**
	Terminate the hash to get the digest
	@param md  The hash state
	@param out [out] The destination of the hash (64 bytes)
	@return CRYPT_OK if successful
*/
int sha512_done(hash_state * md, unsigned char *out)
{
	int i;

	LFH_ARGCHK(md  != NULL);
	LFH_ARGCHK(out != NULL);

	if (md->sha512.curlen >= sizeof(md->sha512.buf)) {
		return CRYPT_INVALID_ARG;
	}

	md->sha512.length += md->sha512.curlen * CONST64(8);

	md->sha512.buf[md->sha512.curlen++] = (unsigned char)0x80;

	/* if the length is currently above 112 bytes we append zeros
	 * then compress.  Then we can fall back to padding zeros and length
	 * encoding like normal.
	 */
	if (md->sha512.curlen > 112) {
		while (md->sha512.curlen < 128) {
			md->sha512.buf[md->sha512.curlen++] = (unsigned char)0;
		}
		s_sha512_compress(md, md->sha512.buf);
		md->sha512.curlen = 0;
	}

	/* pad upto 120 bytes of zeroes
	 * note: that from 112 to 120 is the 64 MSB of the length.  We assume that you won't hash
	 * > 2^64 bits of data... :-)
	 */
	while (md->sha512.curlen < 120) {
		md->sha512.buf[md->sha512.curlen++] = (unsigned char)0;
	}

	STORE64H(md->sha512.length, md->sha512.buf+120);
	s_sha512_compress(md, md->sha512.buf);

	for (i = 0; i < 8; i++) {
		STORE64H(md->sha512.state[i], out+(8*i));
	}
#ifdef LFH_CLEAN_STACK
	zeromem(md, sizeof(hash_state));
#endif
	return CRYPT_OK;
}

/**
	Self-test the hash
	@return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int  sha512_test(void)
{
 #ifndef LFH_TEST
	return CRYPT_NOP;
 #else
	static const struct {
		const char *msg;
		unsigned char hash[64];
	} tests[] = {
	{ "abc",
	 { 0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
		0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
		0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
		0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
		0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
		0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
		0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
		0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f }
	},
	{ "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
	 { 0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda,
		0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc, 0x14, 0x3f,
		0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1,
		0x72, 0x99, 0xae, 0xad, 0xb6, 0x88, 0x90, 0x18,
		0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4,
		0x33, 0x1b, 0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a,
		0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54,
		0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09 }
	},
	};

	int i;
	unsigned char tmp[64];
	hash_state md;

	for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); i++) {
		sha512_init(&md);
		sha512_process(&md, (unsigned char *)tests[i].msg, (unsigned long)XSTRLEN(tests[i].msg));
		sha512_done(&md, tmp);
		if (compare_testvector(tmp, sizeof(tmp), tests[i].hash, sizeof(tests[i].hash), "SHA512", i)) {
		 return CRYPT_FAIL_TESTVECTOR;
		}
	}
	return CRYPT_OK;
	#endif
}

#endif

/**
	@param sha512_224.c
	SHA512/224 hash included in sha512.c
*/

#if defined(LFH_SHA512_224) && defined(LFH_SHA512)

const struct lfh_hash_descriptor sha512_224_desc =
{
	"sha512-224",
	15,
	28,
	128,

	{ 2, 16, 840, 1, 101, 3, 4, 2, 5,  },
	9,

	&sha512_224_init,
	&sha512_process,
	&sha512_224_done,
	&sha512_224_test,
	NULL
};

/**
	Initialize the hash state
	@param md   The hash state you wish to initialize
	@return CRYPT_OK if successful
*/
int sha512_224_init(hash_state * md)
{
	LFH_ARGCHK(md != NULL);

	md->sha512.curlen = 0;
	md->sha512.length = 0;
	md->sha512.state[0] = CONST64(0x8C3D37C819544DA2);
	md->sha512.state[1] = CONST64(0x73E1996689DCD4D6);
	md->sha512.state[2] = CONST64(0x1DFAB7AE32FF9C82);
	md->sha512.state[3] = CONST64(0x679DD514582F9FCF);
	md->sha512.state[4] = CONST64(0x0F6D2B697BD44DA8);
	md->sha512.state[5] = CONST64(0x77E36F7304C48942);
	md->sha512.state[6] = CONST64(0x3F9D85A86A1D36C8);
	md->sha512.state[7] = CONST64(0x1112E6AD91D692A1);
	return CRYPT_OK;
}

/**
	Terminate the hash to get the digest
	@param md  The hash state
	@param out [out] The destination of the hash (48 bytes)
	@return CRYPT_OK if successful
*/
int sha512_224_done(hash_state * md, unsigned char *out)
{
	unsigned char buf[64];

	LFH_ARGCHK(md  != NULL);
	LFH_ARGCHK(out != NULL);

	if (md->sha512.curlen >= sizeof(md->sha512.buf)) {
		return CRYPT_INVALID_ARG;
	}

	sha512_done(md, buf);
	XMEMCPY(out, buf, 28);
#ifdef LFH_CLEAN_STACK
	zeromem(buf, sizeof(buf));
#endif
	return CRYPT_OK;
}

/**
	Self-test the hash
	@return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int  sha512_224_test(void)
{
 #ifndef LFH_TEST
	return CRYPT_NOP;
 #else
	static const struct {
		const char *msg;
		unsigned char hash[28];
	} tests[] = {
	{ "abc",
		{ 0x46, 0x34, 0x27, 0x0F, 0x70, 0x7B, 0x6A, 0x54,
		0xDA, 0xAE, 0x75, 0x30, 0x46, 0x08, 0x42, 0xE2,
		0x0E, 0x37, 0xED, 0x26, 0x5C, 0xEE, 0xE9, 0xA4,
		0x3E, 0x89, 0x24, 0xAA }
	},
	{ "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		{ 0x23, 0xFE, 0xC5, 0xBB, 0x94, 0xD6, 0x0B, 0x23,
		0x30, 0x81, 0x92, 0x64, 0x0B, 0x0C, 0x45, 0x33,
		0x35, 0xD6, 0x64, 0x73, 0x4F, 0xE4, 0x0E, 0x72,
		0x68, 0x67, 0x4A, 0xF9 }
	},
	};

	int i;
	unsigned char tmp[28];
	hash_state md;

	for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); i++) {
		sha512_224_init(&md);
		sha512_224_process(&md, (unsigned char*)tests[i].msg, (unsigned long)XSTRLEN(tests[i].msg));
		sha512_224_done(&md, tmp);
		if (compare_testvector(tmp, sizeof(tmp), tests[i].hash, sizeof(tests[i].hash), "SHA512-224", i)) {
		 return CRYPT_FAIL_TESTVECTOR;
		}
	}
	return CRYPT_OK;
 #endif
}

#endif /* defined(LFH_SHA384) && defined(LFH_SHA512) */
/**
	@param sha512_256.c
	SHA512/256 hash included in sha512.c
*/

#if defined(LFH_SHA512_256) && defined(LFH_SHA512)

const struct lfh_hash_descriptor sha512_256_desc =
{
	"sha512-256",
	16,
	32,
	128,

	{ 2, 16, 840, 1, 101, 3, 4, 2, 6,  },
	9,

	&sha512_256_init,
	&sha512_process,
	&sha512_256_done,
	&sha512_256_test,
	NULL
};

/**
	Initialize the hash state
	@param md   The hash state you wish to initialize
	@return CRYPT_OK if successful
*/
int sha512_256_init(hash_state * md)
{
	LFH_ARGCHK(md != NULL);

	md->sha512.curlen = 0;
	md->sha512.length = 0;
	md->sha512.state[0] = CONST64(0x22312194FC2BF72C);
	md->sha512.state[1] = CONST64(0x9F555FA3C84C64C2);
	md->sha512.state[2] = CONST64(0x2393B86B6F53B151);
	md->sha512.state[3] = CONST64(0x963877195940EABD);
	md->sha512.state[4] = CONST64(0x96283EE2A88EFFE3);
	md->sha512.state[5] = CONST64(0xBE5E1E2553863992);
	md->sha512.state[6] = CONST64(0x2B0199FC2C85B8AA);
	md->sha512.state[7] = CONST64(0x0EB72DDC81C52CA2);
	return CRYPT_OK;
}

/**
	Terminate the hash to get the digest
	@param md  The hash state
	@param out [out] The destination of the hash (48 bytes)
	@return CRYPT_OK if successful
*/
int sha512_256_done(hash_state * md, unsigned char *out)
{
	unsigned char buf[64];

	LFH_ARGCHK(md  != NULL);
	LFH_ARGCHK(out != NULL);

	if (md->sha512.curlen >= sizeof(md->sha512.buf)) {
		return CRYPT_INVALID_ARG;
	}

	sha512_done(md, buf);
	XMEMCPY(out, buf, 32);
#ifdef LFH_CLEAN_STACK
	zeromem(buf, sizeof(buf));
#endif
	return CRYPT_OK;
}

/**
	Self-test the hash
	@return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int  sha512_256_test(void)
{
 #ifndef LFH_TEST
	return CRYPT_NOP;
 #else
	static const struct {
		const char *msg;
		unsigned char hash[32];
	} tests[] = {
	{ "abc",
		{ 0x53, 0x04, 0x8E, 0x26, 0x81, 0x94, 0x1E, 0xF9,
		0x9B, 0x2E, 0x29, 0xB7, 0x6B, 0x4C, 0x7D, 0xAB,
		0xE4, 0xC2, 0xD0, 0xC6, 0x34, 0xFC, 0x6D, 0x46,
		0xE0, 0xE2, 0xF1, 0x31, 0x07, 0xE7, 0xAF, 0x23 }
	},
	{ "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		{ 0x39, 0x28, 0xE1, 0x84, 0xFB, 0x86, 0x90, 0xF8,
		0x40, 0xDA, 0x39, 0x88, 0x12, 0x1D, 0x31, 0xBE,
		0x65, 0xCB, 0x9D, 0x3E, 0xF8, 0x3E, 0xE6, 0x14,
		0x6F, 0xEA, 0xC8, 0x61, 0xE1, 0x9B, 0x56, 0x3A }
	},
	};

	int i;
	unsigned char tmp[32];
	hash_state md;

	for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); i++) {
		sha512_256_init(&md);
		sha512_256_process(&md, (unsigned char*)tests[i].msg, (unsigned long)XSTRLEN(tests[i].msg));
		sha512_256_done(&md, tmp);
		if (compare_testvector(tmp, sizeof(tmp), tests[i].hash, sizeof(tests[i].hash), "SHA512-265", i)) {
		 return CRYPT_FAIL_TESTVECTOR;
		}
	}
	return CRYPT_OK;
 #endif
}

#endif /* defined(LFH_SHA384) && defined(LFH_SHA512) */

#ifdef LFH_SHA3

const struct lfh_hash_descriptor sha3_224_desc =
{
	"sha3-224",                  /* name of hash */
	17,                          /* internal ID */
	28,                          /* Size of digest in octets */
	144,                         /* Input block size in octets */
	{ 2,16,840,1,101,3,4,2,7 },  /* ASN.1 OID */
	9,                           /* Length OID */
	&sha3_224_init,
	&sha3_process,
	&sha3_done,
	&sha3_224_test,
	NULL
};

const struct lfh_hash_descriptor sha3_256_desc =
{
	"sha3-256",                  /* name of hash */
	18,                          /* internal ID */
	32,                          /* Size of digest in octets */
	136,                         /* Input block size in octets */
	{ 2,16,840,1,101,3,4,2,8 },  /* ASN.1 OID */
	9,                           /* Length OID */
	&sha3_256_init,
	&sha3_process,
	&sha3_done,
	&sha3_256_test,
	NULL
};

const struct lfh_hash_descriptor sha3_384_desc =
{
	"sha3-384",                  /* name of hash */
	19,                          /* internal ID */
	48,                          /* Size of digest in octets */
	104,                         /* Input block size in octets */
	{ 2,16,840,1,101,3,4,2,9 },  /* ASN.1 OID */
	9,                           /* Length OID */
	&sha3_384_init,
	&sha3_process,
	&sha3_done,
	&sha3_384_test,
	NULL
};

const struct lfh_hash_descriptor sha3_512_desc =
{
	"sha3-512",                  /* name of hash */
	20,                          /* internal ID */
	64,                          /* Size of digest in octets */
	72,                          /* Input block size in octets */
	{ 2,16,840,1,101,3,4,2,10 }, /* ASN.1 OID */
	9,                           /* Length OID */
	&sha3_512_init,
	&sha3_process,
	&sha3_done,
	&sha3_512_test,
	NULL
};
#endif

#ifdef LFH_KECCAK
const struct lfh_hash_descriptor keccak_224_desc =
{
	"keccak224",                 /* name of hash */
	29,                          /* internal ID */
	28,                          /* Size of digest in octets */
	144,                         /* Input block size in octets */
	{ 0 }, 0,                    /* no ASN.1 OID */
	&sha3_224_init,
	&sha3_process,
	&keccak_done,
	&keccak_224_test,
	NULL
};

const struct lfh_hash_descriptor keccak_256_desc =
{
	"keccak256",                 /* name of hash */
	30,                          /* internal ID */
	32,                          /* Size of digest in octets */
	136,                         /* Input block size in octets */
	{ 0 }, 0,                    /* no ASN.1 OID */
	&sha3_256_init,
	&sha3_process,
	&keccak_done,
	&keccak_256_test,
	NULL
};

const struct lfh_hash_descriptor keccak_384_desc =
{
	"keccak384",                 /* name of hash */
	31,                          /* internal ID */
	48,                          /* Size of digest in octets */
	104,                         /* Input block size in octets */
	{ 0 }, 0,                    /* no ASN.1 OID */
	&sha3_384_init,
	&sha3_process,
	&keccak_done,
	&keccak_384_test,
	NULL
};

const struct lfh_hash_descriptor keccak_512_desc =
{
	"keccak512",                 /* name of hash */
	32,                          /* internal ID */
	64,                          /* Size of digest in octets */
	72,                          /* Input block size in octets */
	{ 0 }, 0,                    /* no ASN.1 OID */
	&sha3_512_init,
	&sha3_process,
	&keccak_done,
	&keccak_512_test,
	NULL
};
#endif

#if defined(LFH_SHA3) || defined(LFH_KECCAK)

#define SHA3_KECCAK_SPONGE_WORDS 25 /* 1600 bits > 200 bytes > 25 x ulong64 */
#define SHA3_KECCAK_ROUNDS 24

static const ulong64 s_keccakf_rndc[24] = {
	CONST64(0x0000000000000001), CONST64(0x0000000000008082),
	CONST64(0x800000000000808a), CONST64(0x8000000080008000),
	CONST64(0x000000000000808b), CONST64(0x0000000080000001),
	CONST64(0x8000000080008081), CONST64(0x8000000000008009),
	CONST64(0x000000000000008a), CONST64(0x0000000000000088),
	CONST64(0x0000000080008009), CONST64(0x000000008000000a),
	CONST64(0x000000008000808b), CONST64(0x800000000000008b),
	CONST64(0x8000000000008089), CONST64(0x8000000000008003),
	CONST64(0x8000000000008002), CONST64(0x8000000000000080),
	CONST64(0x000000000000800a), CONST64(0x800000008000000a),
	CONST64(0x8000000080008081), CONST64(0x8000000000008080),
	CONST64(0x0000000080000001), CONST64(0x8000000080008008)
};

static const unsigned s_keccakf_rotc[24] = {
	1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const unsigned s_keccakf_piln[24] = {
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

static void s_keccakf(ulong64 s[25])
{
	int i, j, round;
	ulong64 t, bc[5];

	for(round = 0; round < SHA3_KECCAK_ROUNDS; round++) {
		for(i = 0; i < 5; i++) {
		 bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];
		}
		for(i = 0; i < 5; i++) {
		 t = bc[(i + 4) % 5] ^ ROL64(bc[(i + 1) % 5], 1);
		 for(j = 0; j < 25; j += 5) {
			s[j + i] ^= t;
		 }
		}
		t = s[1];
		for(i = 0; i < 24; i++) {
		 j = s_keccakf_piln[i];
		 bc[0] = s[j];
		 s[j] = ROL64(t, s_keccakf_rotc[i]);
		 t = bc[0];
		}
		for(j = 0; j < 25; j += 5) {
		 for(i = 0; i < 5; i++) {
			bc[i] = s[j + i];
		 }
		 for(i = 0; i < 5; i++) {
			s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
		 }
		}
		s[0] ^= s_keccakf_rndc[round];
	}
}

static LFH_INLINE int ss_done(hash_state *md, unsigned char *hash, ulong64 pad)
{
	unsigned i;

	LFH_ARGCHK(md   != NULL);
	LFH_ARGCHK(hash != NULL);

	md->sha3.s[md->sha3.word_index] ^= (md->sha3.saved ^ (pad << (md->sha3.byte_index * 8)));
	md->sha3.s[SHA3_KECCAK_SPONGE_WORDS - md->sha3.capacity_words - 1] ^= CONST64(0x8000000000000000);
	s_keccakf(md->sha3.s);

	for(i = 0; i < SHA3_KECCAK_SPONGE_WORDS; i++) {
		STORE64L(md->sha3.s[i], md->sha3.sb + i * 8);
	}

	XMEMCPY(hash, md->sha3.sb, md->sha3.capacity_words * 4);
	return CRYPT_OK;
}

int sha3_224_init(hash_state *md)
{
	LFH_ARGCHK(md != NULL);
	XMEMSET(&md->sha3, 0, sizeof(md->sha3));
	md->sha3.capacity_words = 2 * 224 / (8 * sizeof(ulong64));
	return CRYPT_OK;
}

int sha3_256_init(hash_state *md)
{
	LFH_ARGCHK(md != NULL);
	XMEMSET(&md->sha3, 0, sizeof(md->sha3));
	md->sha3.capacity_words = 2 * 256 / (8 * sizeof(ulong64));
	return CRYPT_OK;
}

int sha3_384_init(hash_state *md)
{
	LFH_ARGCHK(md != NULL);
	XMEMSET(&md->sha3, 0, sizeof(md->sha3));
	md->sha3.capacity_words = 2 * 384 / (8 * sizeof(ulong64));
	return CRYPT_OK;
}

int sha3_512_init(hash_state *md)
{
	LFH_ARGCHK(md != NULL);
	XMEMSET(&md->sha3, 0, sizeof(md->sha3));
	md->sha3.capacity_words = 2 * 512 / (8 * sizeof(ulong64));
	return CRYPT_OK;
}

#ifdef LFH_SHA3
int sha3_shake_init(hash_state *md, int num)
{
	LFH_ARGCHK(md != NULL);
	if (num != 128 && num != 256) return CRYPT_INVALID_ARG;
	XMEMSET(&md->sha3, 0, sizeof(md->sha3));
	md->sha3.capacity_words = (unsigned short)(2 * num / (8 * sizeof(ulong64)));
	return CRYPT_OK;
}
#endif

int sha3_process(hash_state *md, const unsigned char *in, unsigned long inlen)
{
	unsigned old_tail = (8 - md->sha3.byte_index) & 7;

	unsigned long words;
	unsigned tail;
	unsigned long i;

	if (inlen == 0) return CRYPT_OK; /* nothing to do */
	LFH_ARGCHK(md != NULL);
	LFH_ARGCHK(in != NULL);

	if(inlen < old_tail) {       /* have no complete word or haven't started the word yet */
		while (inlen--) md->sha3.saved |= (ulong64) (*(in++)) << ((md->sha3.byte_index++) * 8);
		return CRYPT_OK;
	}

	if(old_tail) {               /* will have one word to process */
		inlen -= old_tail;
		while (old_tail--) md->sha3.saved |= (ulong64) (*(in++)) << ((md->sha3.byte_index++) * 8);
		md->sha3.s[md->sha3.word_index] ^= md->sha3.saved;
		md->sha3.byte_index = 0;
		md->sha3.saved = 0;
		if(++md->sha3.word_index == (SHA3_KECCAK_SPONGE_WORDS - md->sha3.capacity_words)) {
		 s_keccakf(md->sha3.s);
		 md->sha3.word_index = 0;
		}
	}

	words = inlen / sizeof(ulong64);
	tail = inlen - words * sizeof(ulong64);

	for(i = 0; i < words; i++, in += sizeof(ulong64)) {
		ulong64 t;
		LOAD64L(t, in);
		md->sha3.s[md->sha3.word_index] ^= t;
		if(++md->sha3.word_index == (SHA3_KECCAK_SPONGE_WORDS - md->sha3.capacity_words)) {
		 s_keccakf(md->sha3.s);
		 md->sha3.word_index = 0;
		}
	}

	while (tail--) {
		md->sha3.saved |= (ulong64) (*(in++)) << ((md->sha3.byte_index++) * 8);
	}
	return CRYPT_OK;
}

#ifdef LFH_SHA3
int sha3_done(hash_state *md, unsigned char *out)
{
	return ss_done(md, out, CONST64(0x06));
}
#endif

#ifdef LFH_KECCAK
int keccak_done(hash_state *md, unsigned char *out)
{
	return ss_done(md, out, CONST64(0x01));
}
#endif

#ifdef LFH_SHA3
int sha3_shake_done(hash_state *md, unsigned char *out, unsigned long outlen)
{
	unsigned long idx;
	unsigned i;

	if (outlen == 0) return CRYPT_OK; /* nothing to do */
	LFH_ARGCHK(md  != NULL);
	LFH_ARGCHK(out != NULL);

	if (!md->sha3.xof_flag) {
		md->sha3.s[md->sha3.word_index] ^= (md->sha3.saved ^ (CONST64(0x1F) << (md->sha3.byte_index * 8)));
		md->sha3.s[SHA3_KECCAK_SPONGE_WORDS - md->sha3.capacity_words - 1] ^= CONST64(0x8000000000000000);
		s_keccakf(md->sha3.s);
		for(i = 0; i < SHA3_KECCAK_SPONGE_WORDS; i++) {
		 STORE64L(md->sha3.s[i], md->sha3.sb + i * 8);
		}
		md->sha3.byte_index = 0;
		md->sha3.xof_flag = 1;
	}

	for (idx = 0; idx < outlen; idx++) {
		if(md->sha3.byte_index >= (SHA3_KECCAK_SPONGE_WORDS - md->sha3.capacity_words) * 8) {
		 s_keccakf(md->sha3.s);
		 for(i = 0; i < SHA3_KECCAK_SPONGE_WORDS; i++) {
			STORE64L(md->sha3.s[i], md->sha3.sb + i * 8);
		 }
		 md->sha3.byte_index = 0;
		}
		out[idx] = md->sha3.sb[md->sha3.byte_index++];
	}
	return CRYPT_OK;
}

int sha3_shake_memory(int num, const unsigned char *in, unsigned long inlen, unsigned char *out, const unsigned long *outlen)
{
	hash_state md;
	int err;
	LFH_ARGCHK(in  != NULL);
	LFH_ARGCHK(out != NULL);
	LFH_ARGCHK(outlen != NULL);
	if ((err = sha3_shake_init(&md, num))          != CRYPT_OK) return err;
	if ((err = sha3_shake_process(&md, in, inlen)) != CRYPT_OK) return err;
	if ((err = sha3_shake_done(&md, out, *outlen)) != CRYPT_OK) return err;
	return CRYPT_OK;
}
#endif

#endif

#ifdef LFH_SHA3

int sha3_224_test(void)
{
#ifndef LFH_TEST
	return CRYPT_NOP;
#else
	unsigned char buf[200], hash[224 / 8];
	int i;
	hash_state c;
	const unsigned char c1 = 0xa3;

	const unsigned char sha3_224_empty[224 / 8] = {
		0x6b, 0x4e, 0x03, 0x42, 0x36, 0x67, 0xdb, 0xb7,
		0x3b, 0x6e, 0x15, 0x45, 0x4f, 0x0e, 0xb1, 0xab,
		0xd4, 0x59, 0x7f, 0x9a, 0x1b, 0x07, 0x8e, 0x3f,
		0x5b, 0x5a, 0x6b, 0xc7
	};

	const unsigned char sha3_224_0xa3_200_times[224 / 8] = {
		0x93, 0x76, 0x81, 0x6a, 0xba, 0x50, 0x3f, 0x72,
		0xf9, 0x6c, 0xe7, 0xeb, 0x65, 0xac, 0x09, 0x5d,
		0xee, 0xe3, 0xbe, 0x4b, 0xf9, 0xbb, 0xc2, 0xa1,
		0xcb, 0x7e, 0x11, 0xe0
	};

	XMEMSET(buf, c1, sizeof(buf));

	sha3_224_init(&c);
	sha3_done(&c, hash);
	if (compare_testvector(hash, sizeof(hash), sha3_224_empty, sizeof(sha3_224_empty), "SHA3-224", 0)) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	sha3_224_init(&c);
	sha3_process(&c, buf, sizeof(buf) / 2);
	sha3_process(&c, buf + sizeof(buf) / 2, sizeof(buf) / 2);
	sha3_done(&c, hash);
	if (compare_testvector(hash, sizeof(hash), sha3_224_0xa3_200_times, sizeof(sha3_224_0xa3_200_times), "SHA3-224", 1)) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	i = 200;
	sha3_224_init(&c);
	while (i--) {
		sha3_process(&c, &c1, 1);
	}
	sha3_done(&c, hash);
	if (compare_testvector(hash, sizeof(hash), sha3_224_0xa3_200_times, sizeof(sha3_224_0xa3_200_times), "SHA3-224", 2)) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	return CRYPT_OK;
#endif
}

int sha3_256_test(void)
{
#ifndef LFH_TEST
	return CRYPT_NOP;
#else
	unsigned char buf[200], hash[256 / 8];
	int i;
	hash_state c;
	const unsigned char c1 = 0xa3;

	const unsigned char sha3_256_empty[256 / 8] = {
		0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
		0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
		0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
		0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
	};
	const unsigned char sha3_256_0xa3_200_times[256 / 8] = {
		0x79, 0xf3, 0x8a, 0xde, 0xc5, 0xc2, 0x03, 0x07,
		0xa9, 0x8e, 0xf7, 0x6e, 0x83, 0x24, 0xaf, 0xbf,
		0xd4, 0x6c, 0xfd, 0x81, 0xb2, 0x2e, 0x39, 0x73,
		0xc6, 0x5f, 0xa1, 0xbd, 0x9d, 0xe3, 0x17, 0x87
	};

	XMEMSET(buf, c1, sizeof(buf));

	sha3_256_init(&c);
	sha3_done(&c, hash);
	if (compare_testvector(hash, sizeof(hash), sha3_256_empty, sizeof(sha3_256_empty), "SHA3-256", 0)) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	sha3_256_init(&c);
	sha3_process(&c, buf, sizeof(buf));
	sha3_done(&c, hash);
	if (compare_testvector(hash, sizeof(hash), sha3_256_0xa3_200_times, sizeof(sha3_256_0xa3_200_times), "SHA3-256", 1)) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	sha3_256_init(&c);
	sha3_process(&c, buf, sizeof(buf) / 2);
	sha3_process(&c, buf + sizeof(buf) / 2, sizeof(buf) / 2);
	sha3_done(&c, hash);
	if (compare_testvector(hash, sizeof(hash), sha3_256_0xa3_200_times, sizeof(sha3_256_0xa3_200_times), "SHA3-256", 2)) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	i = 200;
	sha3_256_init(&c);
	while (i--) {
		sha3_process(&c, &c1, 1);
	}
	sha3_done(&c, hash);
	if (compare_testvector(hash, sizeof(hash), sha3_256_0xa3_200_times, sizeof(sha3_256_0xa3_200_times), "SHA3-256", 3)) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	/* SHA3-256 byte-by-byte: 135 bytes. Input from [Keccak]. Output
	* matched with sha3sum. */
	sha3_256_init(&c);
	sha3_process(&c, (unsigned char*)
			"\xb7\x71\xd5\xce\xf5\xd1\xa4\x1a"
			"\x93\xd1\x56\x43\xd7\x18\x1d\x2a"
			"\x2e\xf0\xa8\xe8\x4d\x91\x81\x2f"
			"\x20\xed\x21\xf1\x47\xbe\xf7\x32"
			"\xbf\x3a\x60\xef\x40\x67\xc3\x73"
			"\x4b\x85\xbc\x8c\xd4\x71\x78\x0f"
			"\x10\xdc\x9e\x82\x91\xb5\x83\x39"
			"\xa6\x77\xb9\x60\x21\x8f\x71\xe7"
			"\x93\xf2\x79\x7a\xea\x34\x94\x06"
			"\x51\x28\x29\x06\x5d\x37\xbb\x55"
			"\xea\x79\x6f\xa4\xf5\x6f\xd8\x89"
			"\x6b\x49\xb2\xcd\x19\xb4\x32\x15"
			"\xad\x96\x7c\x71\x2b\x24\xe5\x03"
			"\x2d\x06\x52\x32\xe0\x2c\x12\x74"
			"\x09\xd2\xed\x41\x46\xb9\xd7\x5d"
			"\x76\x3d\x52\xdb\x98\xd9\x49\xd3"
			"\xb0\xfe\xd6\xa8\x05\x2f\xbb", 1080 / 8);
	sha3_done(&c, hash);
	if(compare_testvector(hash, sizeof(hash),
			"\xa1\x9e\xee\x92\xbb\x20\x97\xb6"
			"\x4e\x82\x3d\x59\x77\x98\xaa\x18"
			"\xbe\x9b\x7c\x73\x6b\x80\x59\xab"
			"\xfd\x67\x79\xac\x35\xac\x81\xb5", 256 / 8, "SHA3-256", 4)) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	return CRYPT_OK;
#endif
}

int sha3_384_test(void)
{
#ifndef LFH_TEST
	return CRYPT_NOP;
#else
	unsigned char buf[200], hash[384 / 8];
	int i;
	hash_state c;
	const unsigned char c1 = 0xa3;

	const unsigned char sha3_384_0xa3_200_times[384 / 8] = {
		0x18, 0x81, 0xde, 0x2c, 0xa7, 0xe4, 0x1e, 0xf9,
		0x5d, 0xc4, 0x73, 0x2b, 0x8f, 0x5f, 0x00, 0x2b,
		0x18, 0x9c, 0xc1, 0xe4, 0x2b, 0x74, 0x16, 0x8e,
		0xd1, 0x73, 0x26, 0x49, 0xce, 0x1d, 0xbc, 0xdd,
		0x76, 0x19, 0x7a, 0x31, 0xfd, 0x55, 0xee, 0x98,
		0x9f, 0x2d, 0x70, 0x50, 0xdd, 0x47, 0x3e, 0x8f
	};

	XMEMSET(buf, c1, sizeof(buf));

	sha3_384_init(&c);
	sha3_process(&c, buf, sizeof(buf));
	sha3_done(&c, hash);
	if (compare_testvector(hash, sizeof(hash), sha3_384_0xa3_200_times, sizeof(sha3_384_0xa3_200_times), "SHA3-384", 0)) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	sha3_384_init(&c);
	sha3_process(&c, buf, sizeof(buf) / 2);
	sha3_process(&c, buf + sizeof(buf) / 2, sizeof(buf) / 2);
	sha3_done(&c, hash);
	if (compare_testvector(hash, sizeof(hash), sha3_384_0xa3_200_times, sizeof(sha3_384_0xa3_200_times), "SHA3-384", 1)) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	i = 200;
	sha3_384_init(&c);
	while (i--) {
		sha3_process(&c, &c1, 1);
	}
	sha3_done(&c, hash);
	if (compare_testvector(hash, sizeof(hash), sha3_384_0xa3_200_times, sizeof(sha3_384_0xa3_200_times), "SHA3-384", 2)) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	return CRYPT_OK;
#endif
}

int sha3_512_test(void)
{
#ifndef LFH_TEST
	return CRYPT_NOP;
#else
	unsigned char buf[200], hash[512 / 8];
	int i;
	hash_state c;
	const unsigned char c1 = 0xa3;

	const unsigned char sha3_512_0xa3_200_times[512 / 8] = {
		0xe7, 0x6d, 0xfa, 0xd2, 0x20, 0x84, 0xa8, 0xb1,
		0x46, 0x7f, 0xcf, 0x2f, 0xfa, 0x58, 0x36, 0x1b,
		0xec, 0x76, 0x28, 0xed, 0xf5, 0xf3, 0xfd, 0xc0,
		0xe4, 0x80, 0x5d, 0xc4, 0x8c, 0xae, 0xec, 0xa8,
		0x1b, 0x7c, 0x13, 0xc3, 0x0a, 0xdf, 0x52, 0xa3,
		0x65, 0x95, 0x84, 0x73, 0x9a, 0x2d, 0xf4, 0x6b,
		0xe5, 0x89, 0xc5, 0x1c, 0xa1, 0xa4, 0xa8, 0x41,
		0x6d, 0xf6, 0x54, 0x5a, 0x1c, 0xe8, 0xba, 0x00
	};

	XMEMSET(buf, c1, sizeof(buf));

	sha3_512_init(&c);
	sha3_process(&c, buf, sizeof(buf));
	sha3_done(&c, hash);
	if (compare_testvector(hash, sizeof(hash), sha3_512_0xa3_200_times, sizeof(sha3_512_0xa3_200_times), "SHA3-512", 0)) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	sha3_512_init(&c);
	sha3_process(&c, buf, sizeof(buf) / 2);
	sha3_process(&c, buf + sizeof(buf) / 2, sizeof(buf) / 2);
	sha3_done(&c, hash);
	if (compare_testvector(hash, sizeof(hash), sha3_512_0xa3_200_times, sizeof(sha3_512_0xa3_200_times), "SHA3-512", 1)) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	i = 200;
	sha3_512_init(&c);
	while (i--) {
		sha3_process(&c, &c1, 1);
	}
	sha3_done(&c, hash);
	if (compare_testvector(hash, sizeof(hash), sha3_512_0xa3_200_times, sizeof(sha3_512_0xa3_200_times), "SHA3-512", 2)) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	return CRYPT_OK;
#endif
}

int sha3_shake_test(void)
{
#ifndef LFH_TEST
	return CRYPT_NOP;
#else
	unsigned char buf[200], hash[512];
	int i;
	hash_state c;
	const unsigned char c1 = 0xa3;
	unsigned long len;

	const unsigned char shake256_empty[32] = {
		0xab, 0x0b, 0xae, 0x31, 0x63, 0x39, 0x89, 0x43,
		0x04, 0xe3, 0x58, 0x77, 0xb0, 0xc2, 0x8a, 0x9b,
		0x1f, 0xd1, 0x66, 0xc7, 0x96, 0xb9, 0xcc, 0x25,
		0x8a, 0x06, 0x4a, 0x8f, 0x57, 0xe2, 0x7f, 0x2a
	};
	const unsigned char shake256_0xa3_200_times[32] = {
		0x6a, 0x1a, 0x9d, 0x78, 0x46, 0x43, 0x6e, 0x4d,
		0xca, 0x57, 0x28, 0xb6, 0xf7, 0x60, 0xee, 0xf0,
		0xca, 0x92, 0xbf, 0x0b, 0xe5, 0x61, 0x5e, 0x96,
		0x95, 0x9d, 0x76, 0x71, 0x97, 0xa0, 0xbe, 0xeb
	};
	const unsigned char shake128_empty[32] = {
		0x43, 0xe4, 0x1b, 0x45, 0xa6, 0x53, 0xf2, 0xa5,
		0xc4, 0x49, 0x2c, 0x1a, 0xdd, 0x54, 0x45, 0x12,
		0xdd, 0xa2, 0x52, 0x98, 0x33, 0x46, 0x2b, 0x71,
		0xa4, 0x1a, 0x45, 0xbe, 0x97, 0x29, 0x0b, 0x6f
	};
	const unsigned char shake128_0xa3_200_times[32] = {
		0x44, 0xc9, 0xfb, 0x35, 0x9f, 0xd5, 0x6a, 0xc0,
		0xa9, 0xa7, 0x5a, 0x74, 0x3c, 0xff, 0x68, 0x62,
		0xf1, 0x7d, 0x72, 0x59, 0xab, 0x07, 0x52, 0x16,
		0xc0, 0x69, 0x95, 0x11, 0x64, 0x3b, 0x64, 0x39
	};

	XMEMSET(buf, c1, sizeof(buf));

	sha3_shake_init(&c, 256);
	for (i = 0; i < 16; i++) sha3_shake_done(&c, hash, 32); /* get 512 bytes, keep in hash the last 32 */
	if (compare_testvector(hash, sizeof(shake256_empty), shake256_empty, sizeof(shake256_empty), "SHAKE256", 0)) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	len = 512;
	sha3_shake_memory(256, buf, sizeof(buf), hash, &len);
	if (compare_testvector(hash + 480, sizeof(shake256_0xa3_200_times), shake256_0xa3_200_times, sizeof(shake256_0xa3_200_times), "SHAKE256", 1)) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	sha3_shake_init(&c, 256);
	sha3_shake_process(&c, buf, sizeof(buf));
	for (i = 0; i < 16; i++) sha3_shake_done(&c, hash, 32); /* get 512 bytes, keep in hash the last 32 */
	if (compare_testvector(hash, sizeof(shake256_0xa3_200_times), shake256_0xa3_200_times, sizeof(shake256_0xa3_200_times), "SHAKE256", 2)) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	sha3_shake_init(&c, 256);
	sha3_shake_process(&c, buf, sizeof(buf) / 2);
	sha3_shake_process(&c, buf + sizeof(buf) / 2, sizeof(buf) / 2);
	for (i = 0; i < 16; i++) sha3_shake_done(&c, hash, 32); /* get 512 bytes, keep in hash the last 32 */
	if (compare_testvector(hash, sizeof(shake256_0xa3_200_times), shake256_0xa3_200_times, sizeof(shake256_0xa3_200_times), "SHAKE256", 3)) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	i = 200;
	sha3_shake_init(&c, 256);
	while (i--) sha3_shake_process(&c, &c1, 1);
	for (i = 0; i < 16; i++) sha3_shake_done(&c, hash, 32); /* get 512 bytes, keep in hash the last 32 */
	if (compare_testvector(hash, sizeof(shake256_0xa3_200_times), shake256_0xa3_200_times, sizeof(shake256_0xa3_200_times), "SHAKE256", 4)) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	sha3_shake_init(&c, 128);
	for (i = 0; i < 16; i++) sha3_shake_done(&c, hash, 32); /* get 512 bytes, keep in hash the last 32 */
	if (compare_testvector(hash, sizeof(shake128_empty), shake128_empty, sizeof(shake128_empty), "SHAKE128", 0)) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	len = 512;
	sha3_shake_memory(128, buf, sizeof(buf), hash, &len);
	if (compare_testvector(hash + 480, sizeof(shake128_0xa3_200_times), shake128_0xa3_200_times, sizeof(shake128_0xa3_200_times), "SHAKE128", 1)) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	sha3_shake_init(&c, 128);
	sha3_shake_process(&c, buf, sizeof(buf));
	for (i = 0; i < 16; i++) sha3_shake_done(&c, hash, 32); /* get 512 bytes, keep in hash the last 32 */
	if (compare_testvector(hash, sizeof(shake128_0xa3_200_times), shake128_0xa3_200_times, sizeof(shake128_0xa3_200_times), "SHAKE128", 2)) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	sha3_shake_init(&c, 128);
	sha3_shake_process(&c, buf, sizeof(buf) / 2);
	sha3_shake_process(&c, buf + sizeof(buf) / 2, sizeof(buf) / 2);
	for (i = 0; i < 16; i++) sha3_shake_done(&c, hash, 32); /* get 512 bytes, keep in hash the last 32 */
	if (compare_testvector(hash, sizeof(shake128_0xa3_200_times), shake128_0xa3_200_times, sizeof(shake128_0xa3_200_times), "SHAKE128", 3)) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	i = 200;
	sha3_shake_init(&c, 128);
	while (i--) sha3_shake_process(&c, &c1, 1);
	for (i = 0; i < 16; i++) sha3_shake_done(&c, hash, 32); /* get 512 bytes, keep in hash the last 32 */
	if (compare_testvector(hash, sizeof(shake128_0xa3_200_times), shake128_0xa3_200_times, sizeof(shake128_0xa3_200_times), "SHAKE128", 4)) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	return CRYPT_OK;
#endif
}

#endif

#ifdef LFH_KECCAK

int keccak_224_test(void)
{
#ifndef LFH_TEST
	return CRYPT_NOP;
#else
	hash_state c;
	unsigned char hash[MAXBLOCKSIZE];

	keccak_224_init(&c);
	keccak_process(&c, (unsigned char*) "\xcc", 1);
	keccak_done(&c, hash);
	if(compare_testvector(hash, 28,
						 "\xa9\xca\xb5\x9e\xb4\x0a\x10\xb2"
						 "\x46\x29\x0f\x2d\x60\x86\xe3\x2e"
						 "\x36\x89\xfa\xf1\xd2\x6b\x47\x0c"
						 "\x89\x9f\x28\x02", 28,
						 "KECCAK-224", 0) != 0) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	keccak_224_init(&c);
	keccak_process(&c, (unsigned char*)"\x41\xfb", 2);
	keccak_done(&c, hash);
	if(compare_testvector(hash, 28,
						 "\x61\x5b\xa3\x67\xaf\xdc\x35\xaa"
						 "\xc3\x97\xbc\x7e\xb5\xd5\x8d\x10"
						 "\x6a\x73\x4b\x24\x98\x6d\x5d\x97"
						 "\x8f\xef\xd6\x2c", 28,
						 "KECCAK-224", 1) != 0) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	keccak_224_init(&c);
	keccak_process(&c, (unsigned char*)
					"\x52\xa6\x08\xab\x21\xcc\xdd\x8a"
					"\x44\x57\xa5\x7e\xde\x78\x21\x76", 16);
	keccak_done(&c, hash);
	if(compare_testvector(hash, 28,
						 "\x56\x79\xcd\x50\x9c\x51\x20\xaf"
						 "\x54\x79\x5c\xf4\x77\x14\x96\x41"
						 "\xcf\x27\xb2\xeb\xb6\xa5\xf9\x03"
						 "\x40\x70\x4e\x57", 28,
						 "KECCAK-224", 2) != 0) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	keccak_224_init(&c);
	keccak_process(&c, (unsigned char*)
					"\x43\x3c\x53\x03\x13\x16\x24\xc0"
					"\x02\x1d\x86\x8a\x30\x82\x54\x75"
					"\xe8\xd0\xbd\x30\x52\xa0\x22\x18"
					"\x03\x98\xf4\xca\x44\x23\xb9\x82"
					"\x14\xb6\xbe\xaa\xc2\x1c\x88\x07"
					"\xa2\xc3\x3f\x8c\x93\xbd\x42\xb0"
					"\x92\xcc\x1b\x06\xce\xdf\x32\x24"
					"\xd5\xed\x1e\xc2\x97\x84\x44\x4f"
					"\x22\xe0\x8a\x55\xaa\x58\x54\x2b"
					"\x52\x4b\x02\xcd\x3d\x5d\x5f\x69"
					"\x07\xaf\xe7\x1c\x5d\x74\x62\x22"
					"\x4a\x3f\x9d\x9e\x53\xe7\xe0\x84"
					"\x6d\xcb\xb4\xce", 100);
	keccak_done(&c, hash);
	if(compare_testvector(hash, 28,
						 "\x62\xb1\x0f\x1b\x62\x36\xeb\xc2"
						 "\xda\x72\x95\x77\x42\xa8\xd4\xe4"
						 "\x8e\x21\x3b\x5f\x89\x34\x60\x4b"
						 "\xfd\x4d\x2c\x3a", 28,
						 "KECCAK-224", 3) != 0) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	return CRYPT_OK;
#endif
}

int keccak_256_test(void)
{
#ifndef LFH_TEST
	return CRYPT_NOP;
#else
	hash_state c;
	unsigned char hash[MAXBLOCKSIZE];

	keccak_256_init(&c);
	keccak_process(&c, (unsigned char*) "\xcc", 1);
	keccak_done(&c, hash);
	if(compare_testvector(hash, 32,
						 "\xee\xad\x6d\xbf\xc7\x34\x0a\x56"
						 "\xca\xed\xc0\x44\x69\x6a\x16\x88"
						 "\x70\x54\x9a\x6a\x7f\x6f\x56\x96"
						 "\x1e\x84\xa5\x4b\xd9\x97\x0b\x8a", 32,
						 "KECCAK-256", 0) != 0) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	keccak_256_init(&c);
	keccak_process(&c, (unsigned char*)"\x41\xfb", 2);
	keccak_done(&c, hash);
	if(compare_testvector(hash, 32,
						 "\xa8\xea\xce\xda\x4d\x47\xb3\x28"
						 "\x1a\x79\x5a\xd9\xe1\xea\x21\x22"
						 "\xb4\x07\xba\xf9\xaa\xbc\xb9\xe1"
						 "\x8b\x57\x17\xb7\x87\x35\x37\xd2", 32,
						 "KECCAK-256", 1) != 0) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	keccak_256_init(&c);
	keccak_process(&c, (unsigned char*)
					"\x52\xa6\x08\xab\x21\xcc\xdd\x8a"
					"\x44\x57\xa5\x7e\xde\x78\x21\x76", 16);
	keccak_done(&c, hash);
	if(compare_testvector(hash, 32,
						 "\x0e\x32\xde\xfa\x20\x71\xf0\xb5"
						 "\xac\x0e\x6a\x10\x8b\x84\x2e\xd0"
						 "\xf1\xd3\x24\x97\x12\xf5\x8e\xe0"
						 "\xdd\xf9\x56\xfe\x33\x2a\x5f\x95", 32,
						 "KECCAK-256", 2) != 0) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	keccak_256_init(&c);
	keccak_process(&c, (unsigned char*)
					"\x43\x3c\x53\x03\x13\x16\x24\xc0"
					"\x02\x1d\x86\x8a\x30\x82\x54\x75"
					"\xe8\xd0\xbd\x30\x52\xa0\x22\x18"
					"\x03\x98\xf4\xca\x44\x23\xb9\x82"
					"\x14\xb6\xbe\xaa\xc2\x1c\x88\x07"
					"\xa2\xc3\x3f\x8c\x93\xbd\x42\xb0"
					"\x92\xcc\x1b\x06\xce\xdf\x32\x24"
					"\xd5\xed\x1e\xc2\x97\x84\x44\x4f"
					"\x22\xe0\x8a\x55\xaa\x58\x54\x2b"
					"\x52\x4b\x02\xcd\x3d\x5d\x5f\x69"
					"\x07\xaf\xe7\x1c\x5d\x74\x62\x22"
					"\x4a\x3f\x9d\x9e\x53\xe7\xe0\x84"
					"\x6d\xcb\xb4\xce", 100);
	keccak_done(&c, hash);
	if(compare_testvector(hash, 32,
						 "\xce\x87\xa5\x17\x3b\xff\xd9\x23"
						 "\x99\x22\x16\x58\xf8\x01\xd4\x5c"
						 "\x29\x4d\x90\x06\xee\x9f\x3f\x9d"
						 "\x41\x9c\x8d\x42\x77\x48\xdc\x41", 32,
						 "KECCAK-256", 3) != 0) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	return CRYPT_OK;
#endif
}

int keccak_384_test(void)
{
#ifndef LFH_TEST
	return CRYPT_NOP;
#else
	hash_state c;
	unsigned char hash[MAXBLOCKSIZE];

	keccak_384_init(&c);
	keccak_process(&c, (unsigned char*) "\xcc", 1);
	keccak_done(&c, hash);
	if(compare_testvector(hash, 48,
						 "\x1b\x84\xe6\x2a\x46\xe5\xa2\x01"
						 "\x86\x17\x54\xaf\x5d\xc9\x5c\x4a"
						 "\x1a\x69\xca\xf4\xa7\x96\xae\x40"
						 "\x56\x80\x16\x1e\x29\x57\x26\x41"
						 "\xf5\xfa\x1e\x86\x41\xd7\x95\x83"
						 "\x36\xee\x7b\x11\xc5\x8f\x73\xe9", 48,
						 "KECCAK-384", 0) != 0) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	keccak_384_init(&c);
	keccak_process(&c, (unsigned char*)"\x41\xfb", 2);
	keccak_done(&c, hash);
	if(compare_testvector(hash, 48,
						 "\x49\x5c\xce\x27\x14\xcd\x72\xc8"
						 "\xc5\x3c\x33\x63\xd2\x2c\x58\xb5"
						 "\x59\x60\xfe\x26\xbe\x0b\xf3\xbb"
						 "\xc7\xa3\x31\x6d\xd5\x63\xad\x1d"
						 "\xb8\x41\x0e\x75\xee\xfe\xa6\x55"
						 "\xe3\x9d\x46\x70\xec\x0b\x17\x92", 48,
						 "KECCAK-384", 1) != 0) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	keccak_384_init(&c);
	keccak_process(&c, (unsigned char*)
					"\x52\xa6\x08\xab\x21\xcc\xdd\x8a"
					"\x44\x57\xa5\x7e\xde\x78\x21\x76", 16);
	keccak_done(&c, hash);
	if(compare_testvector(hash, 48,
						 "\x18\x42\x2a\xc1\xd3\xa1\xe5\x4b"
						 "\xad\x87\x68\x83\xd2\xd6\xdd\x65"
						 "\xf6\x5c\x1d\x5f\x33\xa7\x12\x5c"
						 "\xc4\xc1\x86\x40\x5a\x12\xed\x64"
						 "\xba\x96\x67\x2e\xed\xda\x8c\x5a"
						 "\x63\x31\xd2\x86\x83\xf4\x88\xeb", 48,
						 "KECCAK-384", 2) != 0) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	keccak_384_init(&c);
	keccak_process(&c, (unsigned char*)
					"\x43\x3c\x53\x03\x13\x16\x24\xc0"
					"\x02\x1d\x86\x8a\x30\x82\x54\x75"
					"\xe8\xd0\xbd\x30\x52\xa0\x22\x18"
					"\x03\x98\xf4\xca\x44\x23\xb9\x82"
					"\x14\xb6\xbe\xaa\xc2\x1c\x88\x07"
					"\xa2\xc3\x3f\x8c\x93\xbd\x42\xb0"
					"\x92\xcc\x1b\x06\xce\xdf\x32\x24"
					"\xd5\xed\x1e\xc2\x97\x84\x44\x4f"
					"\x22\xe0\x8a\x55\xaa\x58\x54\x2b"
					"\x52\x4b\x02\xcd\x3d\x5d\x5f\x69"
					"\x07\xaf\xe7\x1c\x5d\x74\x62\x22"
					"\x4a\x3f\x9d\x9e\x53\xe7\xe0\x84"
					"\x6d\xcb\xb4\xce", 100);
	keccak_done(&c, hash);
	if(compare_testvector(hash, 48,
						 "\x13\x51\x14\x50\x8d\xd6\x3e\x27"
						 "\x9e\x70\x9c\x26\xf7\x81\x7c\x04"
						 "\x82\x76\x6c\xde\x49\x13\x2e\x3e"
						 "\xdf\x2e\xed\xd8\x99\x6f\x4e\x35"
						 "\x96\xd1\x84\x10\x0b\x38\x48\x68"
						 "\x24\x9f\x1d\x8b\x8f\xda\xa2\xc9", 48,
						 "KECCAK-384", 3) != 0) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	return CRYPT_OK;
#endif
}

int keccak_512_test(void)
{
#ifndef LFH_TEST
	return CRYPT_NOP;
#else
	hash_state c;
	unsigned char hash[MAXBLOCKSIZE];

	keccak_512_init(&c);
	keccak_process(&c, (unsigned char*) "\xcc", 1);
	keccak_done(&c, hash);
	if(compare_testvector(hash, 64,
						 "\x86\x30\xc1\x3c\xbd\x06\x6e\xa7"
						 "\x4b\xbe\x7f\xe4\x68\xfe\xc1\xde"
						 "\xe1\x0e\xdc\x12\x54\xfb\x4c\x1b"
						 "\x7c\x5f\xd6\x9b\x64\x6e\x44\x16"
						 "\x0b\x8c\xe0\x1d\x05\xa0\x90\x8c"
						 "\xa7\x90\xdf\xb0\x80\xf4\xb5\x13"
						 "\xbc\x3b\x62\x25\xec\xe7\xa8\x10"
						 "\x37\x14\x41\xa5\xac\x66\x6e\xb9", 64,
						 "KECCAK-512", 0) != 0) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	keccak_512_init(&c);
	keccak_process(&c, (unsigned char*)"\x41\xfb", 2);
	keccak_done(&c, hash);
	if(compare_testvector(hash, 64,
						 "\x55\x1d\xa6\x23\x6f\x8b\x96\xfc"
						 "\xe9\xf9\x7f\x11\x90\xe9\x01\x32"
						 "\x4f\x0b\x45\xe0\x6d\xbb\xb5\xcd"
						 "\xb8\x35\x5d\x6e\xd1\xdc\x34\xb3"
						 "\xf0\xea\xe7\xdc\xb6\x86\x22\xff"
						 "\x23\x2f\xa3\xce\xce\x0d\x46\x16"
						 "\xcd\xeb\x39\x31\xf9\x38\x03\x66"
						 "\x2a\x28\xdf\x1c\xd5\x35\xb7\x31", 64,
						 "KECCAK-512", 1) != 0) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	keccak_512_init(&c);
	keccak_process(&c, (unsigned char*)
					"\x52\xa6\x08\xab\x21\xcc\xdd\x8a"
					"\x44\x57\xa5\x7e\xde\x78\x21\x76", 16);
	keccak_done(&c, hash);
	if(compare_testvector(hash, 64,
						 "\x4b\x39\xd3\xda\x5b\xcd\xf4\xd9"
						 "\xb7\x69\x01\x59\x95\x64\x43\x11"
						 "\xc1\x4c\x43\x5b\xf7\x2b\x10\x09"
						 "\xd6\xdd\x71\xb0\x1a\x63\xb9\x7c"
						 "\xfb\x59\x64\x18\xe8\xe4\x23\x42"
						 "\xd1\x17\xe0\x74\x71\xa8\x91\x43"
						 "\x14\xba\x7b\x0e\x26\x4d\xad\xf0"
						 "\xce\xa3\x81\x86\x8c\xbd\x43\xd1", 64,
						 "KECCAK-512", 2) != 0) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	keccak_512_init(&c);
	keccak_process(&c, (unsigned char*)
					"\x43\x3c\x53\x03\x13\x16\x24\xc0"
					"\x02\x1d\x86\x8a\x30\x82\x54\x75"
					"\xe8\xd0\xbd\x30\x52\xa0\x22\x18"
					"\x03\x98\xf4\xca\x44\x23\xb9\x82"
					"\x14\xb6\xbe\xaa\xc2\x1c\x88\x07"
					"\xa2\xc3\x3f\x8c\x93\xbd\x42\xb0"
					"\x92\xcc\x1b\x06\xce\xdf\x32\x24"
					"\xd5\xed\x1e\xc2\x97\x84\x44\x4f"
					"\x22\xe0\x8a\x55\xaa\x58\x54\x2b"
					"\x52\x4b\x02\xcd\x3d\x5d\x5f\x69"
					"\x07\xaf\xe7\x1c\x5d\x74\x62\x22"
					"\x4a\x3f\x9d\x9e\x53\xe7\xe0\x84"
					"\x6d\xcb\xb4\xce", 100);
	keccak_done(&c, hash);
	if(compare_testvector(hash, 64,
						 "\x52\x7d\x28\xe3\x41\xe6\xb1\x4f"
						 "\x46\x84\xad\xb4\xb8\x24\xc4\x96"
						 "\xc6\x48\x2e\x51\x14\x95\x65\xd3"
						 "\xd1\x72\x26\x82\x88\x84\x30\x6b"
						 "\x51\xd6\x14\x8a\x72\x62\x2c\x2b"
						 "\x75\xf5\xd3\x51\x0b\x79\x9d\x8b"
						 "\xdc\x03\xea\xed\xe4\x53\x67\x6a"
						 "\x6e\xc8\xfe\x03\xa1\xad\x0e\xab", 64,
						 "KECCAK-512", 3) != 0) {
		return CRYPT_FAIL_TESTVECTOR;
	}

	return CRYPT_OK;
#endif
}

#endif

#ifndef LFH_NO_FILE
/**
	@file hash_file.c
	Hash a file, Tom St Denis
*/

/**
	@param hash   The index of the hash desired
	@param fname  The name of the file you wish to hash
	@param out    [out] The destination of the digest
	@param outlen [in/out] The max size and resulting size of the message digest
	@result CRYPT_OK if successful
*/
int hash_file(int hash, const char *fname, unsigned char *out, unsigned long *outlen)
{
	FILE *in;
	int err;
	LFH_ARGCHK(fname  != NULL);
	LFH_ARGCHK(out    != NULL);
	LFH_ARGCHK(outlen != NULL);

	if ((err = hash_is_valid(hash)) != CRYPT_OK) {
		return err;
	}

	in = fopen(fname, "rb");
	if (in == NULL) {
		return CRYPT_FILE_NOTFOUND;
	}

	err = hash_filehandle(hash, in, out, outlen);
	if (fclose(in) != 0) {
		return CRYPT_ERROR;
	}

	return err;
}
#endif /* #ifndef LFH_NO_FILE */

#ifndef LFH_NO_FILE
/**
	@file hash_filehandle.c
	Hash open files, Tom St Denis
*/

/**
	Hash data from an open file handle.
	@param hash   The index of the hash you want to use
	@param in     The FILE* handle of the file you want to hash
	@param out    [out] The destination of the digest
	@param outlen [in/out] The max size and resulting size of the digest
	@result CRYPT_OK if successful
*/
int hash_filehandle(int hash, FILE *in, unsigned char *out, unsigned long *outlen)
{
	hash_state md;
	unsigned char *buf;
	size_t x;
	int err;

	LFH_ARGCHK(out    != NULL);
	LFH_ARGCHK(outlen != NULL);
	LFH_ARGCHK(in     != NULL);

	if ((buf = XMALLOC(LFH_FILE_READ_BUFSIZE)) == NULL) {
		return CRYPT_MEM;
	}

	if ((err = hash_is_valid(hash)) != CRYPT_OK) {
		goto LBL_ERR;
	}

	if (*outlen < hash_descriptor[hash].hashsize) {
		*outlen = hash_descriptor[hash].hashsize;
		err = CRYPT_BUFFER_OVERFLOW;
		goto LBL_ERR;
	}
	if ((err = hash_descriptor[hash].init(&md)) != CRYPT_OK) {
		goto LBL_ERR;
	}

	do {
		x = fread(buf, 1, LFH_FILE_READ_BUFSIZE, in);
		if ((err = hash_descriptor[hash].process(&md, buf, (unsigned long)x)) != CRYPT_OK) {
			goto LBL_CLEANBUF;
		}
	} while (x == LFH_FILE_READ_BUFSIZE);
	if ((err = hash_descriptor[hash].done(&md, out)) == CRYPT_OK) {
		*outlen = hash_descriptor[hash].hashsize;
	}

LBL_CLEANBUF:
	zeromem(buf, LFH_FILE_READ_BUFSIZE);
LBL_ERR:
	XFREE(buf);
	return err;
}
#endif /* #ifndef LFH_NO_FILE */

#ifdef LFH_HASH_HELPERS
/**
	@file hash_memory.c
	Hash memory helper, Tom St Denis
*/

/**
	Hash a block of memory and store the digest.
	@param hash   The index of the hash you wish to use
	@param in     The data you wish to hash
	@param inlen  The length of the data to hash (octets)
	@param out    [out] Where to store the digest
	@param outlen [in/out] Max size and resulting size of the digest
	@return CRYPT_OK if successful
*/
int hash_memory(int hash, const unsigned char *in, unsigned long inlen, unsigned char *out, unsigned long *outlen)
{
	hash_state *md;
	int err;

	LFH_ARGCHK(in     != NULL);
	LFH_ARGCHK(out    != NULL);
	LFH_ARGCHK(outlen != NULL);

	if ((err = hash_is_valid(hash)) != CRYPT_OK) {
		return err;
	}

	if (*outlen < hash_descriptor[hash].hashsize) {
		*outlen = hash_descriptor[hash].hashsize;
		return CRYPT_BUFFER_OVERFLOW;
	}

	md = XMALLOC(sizeof(hash_state));
	if (md == NULL) {
		return CRYPT_MEM;
	}

	if ((err = hash_descriptor[hash].init(md)) != CRYPT_OK) {
		goto LBL_ERR;
	}
	if ((err = hash_descriptor[hash].process(md, in, inlen)) != CRYPT_OK) {
		goto LBL_ERR;
	}
	err = hash_descriptor[hash].done(md, out);
	*outlen = hash_descriptor[hash].hashsize;
LBL_ERR:
#ifdef LFH_CLEAN_STACK
	zeromem(md, sizeof(hash_state));
#endif
	XFREE(md);

	return err;
}
#endif /* #ifdef LFH_HASH_HELPERS */
#include <stdarg.h>

#ifdef LFH_HASH_HELPERS
/**
	@file hash_memory_multi.c
	Hash (multiple buffers) memory helper, Tom St Denis
*/

/**
	Hash multiple (non-adjacent) blocks of memory at once.
	@param hash   The index of the hash you wish to use
	@param out    [out] Where to store the digest
	@param outlen [in/out] Max size and resulting size of the digest
	@param in     The data you wish to hash
	@param inlen  The length of the data to hash (octets)
	@param ...    tuples of (data,len) pairs to hash, terminated with a (NULL,x) (x=don't care)
	@return CRYPT_OK if successful
*/
int hash_memory_multi(int hash, unsigned char *out, unsigned long *outlen,
						const unsigned char *in, unsigned long inlen, ...)
{
	hash_state          *md;
	int                  err;
	va_list              args;
	const unsigned char *curptr;
	unsigned long        curlen;

	LFH_ARGCHK(in     != NULL);
	LFH_ARGCHK(out    != NULL);
	LFH_ARGCHK(outlen != NULL);

	if ((err = hash_is_valid(hash)) != CRYPT_OK) {
		return err;
	}

	if (*outlen < hash_descriptor[hash].hashsize) {
		*outlen = hash_descriptor[hash].hashsize;
		return CRYPT_BUFFER_OVERFLOW;
	}

	md = XMALLOC(sizeof(hash_state));
	if (md == NULL) {
		return CRYPT_MEM;
	}

	if ((err = hash_descriptor[hash].init(md)) != CRYPT_OK) {
		goto LBL_ERR;
	}

	va_start(args, inlen);
	curptr = in;
	curlen = inlen;
	for (;;) {
		if ((err = hash_descriptor[hash].process(md, curptr, curlen)) != CRYPT_OK) {
			goto LBL_ERR;
		}
		curptr = va_arg(args, const unsigned char*);
		if (curptr == NULL) {
			break;
		}
		curlen = va_arg(args, unsigned long);
	}
	err = hash_descriptor[hash].done(md, out);
	*outlen = hash_descriptor[hash].hashsize;
LBL_ERR:
#ifdef LFH_CLEAN_STACK
	zeromem(md, sizeof(hash_state));
#endif
	XFREE(md);
	va_end(args);
	return err;
}
#endif /* #ifdef LFH_HASH_HELPERS */

/**
	@file compare_testvector.c
	Function to compare two testvectors and print a (detailed) error-message if required, Steffen Jaeckel
*/

#if defined(LFH_TEST) && defined(LFH_TEST_DBG)
static void s_print_hex(const char* what, const void* v, const unsigned long l)
{
	const unsigned char* p = v;
	unsigned long x, y = 0, z;
	fprintf(stderr, "%s contents: \n", what);
	for (x = 0; x < l; ) {
		fprintf(stderr, "%02X ", p[x]);
		if (!(++x % 16) || x == l) {
		 if((x % 16) != 0) {
			z = 16 - (x % 16);
			if(z >= 8)
				fprintf(stderr, " ");
			for (; z != 0; --z) {
				fprintf(stderr, "   ");
			}
		 }
		 fprintf(stderr, " | ");
		 for(; y < x; y++) {
			if((y % 8) == 0)
				fprintf(stderr, " ");
			if(isgraph(p[y]))
				fprintf(stderr, "%c", p[y]);
			else
				fprintf(stderr, ".");
		 }
		 fprintf(stderr, "\n");
		}
		else if((x % 8) == 0) {
		 fprintf(stderr, " ");
		}
	}
}
#endif

/**
	Compare two test-vectors

	@param is             The data as it is
	@param is_len         The length of is
	@param should         The data as it should
	@param should_len     The length of should
	@param what           The type of the data
	@param which          The iteration count
	@return 0 on equality, -1 or 1 on difference
*/
int compare_testvector(const void* is, const unsigned long is_len, const void* should, const unsigned long should_len, const char* what, int which)
{
	int res = 0;
	if(is_len != should_len) {
		res = is_len > should_len ? -1 : 1;
	} else {
		res = XMEMCMP(is, should, is_len);
	}
#if defined(LFH_TEST) && defined(LFH_TEST_DBG)
	if (res != 0) {
		fprintf(stderr, "Testvector #%i(0x%x) of %s failed:\n", which, which, what);
		s_print_hex("SHOULD", should, should_len);
		s_print_hex("IS    ", is, is_len);
#if LFH_TEST_DBG > 1
	} else {
		fprintf(stderr, "Testvector #%i(0x%x) of %s passed!\n", which, which, what);
#endif
	}
#else
	LFH_UNUSED_PARAM(which);
	LFH_UNUSED_PARAM(what);
#endif

	return res;
}

/**
	@file error_to_string.c
	Convert error codes to ASCII strings, Tom St Denis
*/

static const char * const err_2_str[] =
{
	"CRYPT_OK",
	"CRYPT_ERROR",
	"Non-fatal 'no-operation' requested.",

	"Invalid key size.",
	"Invalid number of rounds for block cipher.",
	"Algorithm failed test vectors.",

	"Buffer overflow.",
	"Invalid input packet.",

	"Invalid number of bits for a PRNG.",
	"Error reading the PRNG.",

	"Invalid cipher specified.",
	"Invalid hash specified.",
	"Invalid PRNG specified.",

	"Out of memory.",

	"Invalid PK key or key type specified for function.",
	"A private PK key is required.",

	"Invalid argument provided.",
	"File Not Found",

	"Invalid PK type.",

	"An overflow of a value was detected/prevented.",

	"An ASN.1 decoding error occurred.",

	"The input was longer than expected.",

	"Invalid sized parameter.",

	"Invalid size for prime.",

	"Invalid padding.",

	"Hash applied to too many bits.",
};

/**
	Convert an LTC error code to ASCII
	@param err    The error code
	@return A pointer to the ASCII NUL terminated string for the error or "Invalid error code." if the err code was not valid.
*/
const char *error_to_string(int err)
{
	if (err < 0 || err >= (int)(sizeof(err_2_str)/sizeof(err_2_str[0]))) {
		return "Invalid error code.";
	}
	return err_2_str[err];
}

/**
	@file crypt_argchk.c
	Perform argument checking, Tom St Denis
*/

#if (ARGTYPE == 0)
void crypt_argchk(const char *v, const char *s, int d)
{
 fprintf(stderr, "LFH_ARGCHK '%s' failure on line %d of file %s\n",
		 v, d, s);
 abort();
}
#endif

/**
	@file crypt_find_hash.c
	Find a hash, Tom St Denis
*/

/**
	Find a registered hash by name
	@param name   The name of the hash to look for
	@return >= 0 if found, -1 if not present
*/
int find_hash(const char *name)
{
	int x;
	LFH_ARGCHK(name != NULL);
	LFH_MUTEX_LOCK(&lfh_hash_mutex);
	for (x = 0; x < TAB_SIZE; x++) {
		if (hash_descriptor[x].name != NULL && XSTRCMP(hash_descriptor[x].name, name) == 0) {
			LFH_MUTEX_UNLOCK(&lfh_hash_mutex);
			return x;
		}
	}
	LFH_MUTEX_UNLOCK(&lfh_hash_mutex);
	return -1;
}

/**
	@file crypt_find_hash_any.c
	Find a hash, Tom St Denis
*/

/**
	Find a hash flexibly.  First by name then if not present by digest size
	@param name        The name of the hash desired
	@param digestlen   The minimum length of the digest size (octets)
	@return >= 0 if found, -1 if not present
*/int find_hash_any(const char *name, int digestlen)
{
	int x, y, z;
	LFH_ARGCHK(name != NULL);

	x = find_hash(name);
	if (x != -1) return x;

	LFH_MUTEX_LOCK(&lfh_hash_mutex);
	y = MAXBLOCKSIZE+1;
	z = -1;
	for (x = 0; x < TAB_SIZE; x++) {
		if (hash_descriptor[x].name == NULL) {
			continue;
		}
		if ((int)hash_descriptor[x].hashsize >= digestlen && (int)hash_descriptor[x].hashsize < y) {
			z = x;
			y = hash_descriptor[x].hashsize;
		}
	}
	LFH_MUTEX_UNLOCK(&lfh_hash_mutex);
	return z;
}

/**
	@file crypt_find_hash_id.c
	Find hash by ID, Tom St Denis
*/

/**
	Find a hash by ID number
	@param ID    The ID (not same as index) of the hash to find
	@return >= 0 if found, -1 if not present
*/
int find_hash_id(unsigned char ID)
{
	int x;
	LFH_MUTEX_LOCK(&lfh_hash_mutex);
	for (x = 0; x < TAB_SIZE; x++) {
		if (hash_descriptor[x].ID == ID) {
			x = (hash_descriptor[x].name == NULL) ? -1 : x;
			LFH_MUTEX_UNLOCK(&lfh_hash_mutex);
			return x;
		}
	}
	LFH_MUTEX_UNLOCK(&lfh_hash_mutex);
	return -1;
}

/**
	@file crypt_find_hash_oid.c
	Find a hash, Tom St Denis
*/

int find_hash_oid(const unsigned long *ID, unsigned long IDlen)
{
	int x;
	LFH_ARGCHK(ID != NULL);
	LFH_MUTEX_LOCK(&lfh_hash_mutex);
	for (x = 0; x < TAB_SIZE; x++) {
		if (hash_descriptor[x].name != NULL && hash_descriptor[x].OIDlen == IDlen && !XMEMCMP(hash_descriptor[x].OID, ID, sizeof(unsigned long) * IDlen)) {
			LFH_MUTEX_UNLOCK(&lfh_hash_mutex);
			return x;
		}
	}
	LFH_MUTEX_UNLOCK(&lfh_hash_mutex);
	return -1;
}

/**
	@file crypt_hash_descriptor.c
	Stores the hash descriptor table, Tom St Denis
*/

struct lfh_hash_descriptor hash_descriptor[TAB_SIZE] = {
{ NULL, 0, 0, 0, { 0 }, 0, NULL, NULL, NULL, NULL, NULL }
};

LFH_MUTEX_GLOBAL(lfh_hash_mutex)

/**
	@file crypt_hash_is_valid.c
	Determine if hash is valid, Tom St Denis
*/

/*
	Test if a hash index is valid
	@param idx   The index of the hash to search for
	@return CRYPT_OK if valid
*/
int hash_is_valid(int idx)
{
	LFH_MUTEX_LOCK(&lfh_hash_mutex);
	if (idx < 0 || idx >= TAB_SIZE || hash_descriptor[idx].name == NULL) {
		LFH_MUTEX_UNLOCK(&lfh_hash_mutex);
		return CRYPT_INVALID_HASH;
	}
	LFH_MUTEX_UNLOCK(&lfh_hash_mutex);
	return CRYPT_OK;
}

/**
	@file crypt_register_all_hashes.c

	Steffen Jaeckel
*/

#define REGISTER_HASH(h) do {\
	LFH_ARGCHK(register_hash(h) != -1); \
} while(0)

int register_all_hashes(void)
{
#ifdef LFH_TIGER
	REGISTER_HASH(&tiger_desc);
#endif
#ifdef LFH_MD2
	REGISTER_HASH(&md2_desc);
#endif
#ifdef LFH_MD4
	REGISTER_HASH(&md4_desc);
#endif
#ifdef LFH_MD5
	REGISTER_HASH(&md5_desc);
#endif
#ifdef LFH_SHA1
	REGISTER_HASH(&sha1_desc);
#endif
#ifdef LFH_SHA224
	REGISTER_HASH(&sha224_desc);
#endif
#ifdef LFH_SHA256
	REGISTER_HASH(&sha256_desc);
#endif
#ifdef LFH_SHA384
	REGISTER_HASH(&sha384_desc);
#endif
#ifdef LFH_SHA512
	REGISTER_HASH(&sha512_desc);
#endif
#ifdef LFH_SHA512_224
	REGISTER_HASH(&sha512_224_desc);
#endif
#ifdef LFH_SHA512_256
	REGISTER_HASH(&sha512_256_desc);
#endif
#ifdef LFH_SHA3
	REGISTER_HASH(&sha3_224_desc);
	REGISTER_HASH(&sha3_256_desc);
	REGISTER_HASH(&sha3_384_desc);
	REGISTER_HASH(&sha3_512_desc);
#endif
#ifdef LFH_KECCAK
	REGISTER_HASH(&keccak_224_desc);
	REGISTER_HASH(&keccak_256_desc);
	REGISTER_HASH(&keccak_384_desc);
	REGISTER_HASH(&keccak_512_desc);
#endif
#ifdef LFH_RIPEMD128
	REGISTER_HASH(&rmd128_desc);
#endif
#ifdef LFH_RIPEMD160
	REGISTER_HASH(&rmd160_desc);
#endif
#ifdef LFH_RIPEMD256
	REGISTER_HASH(&rmd256_desc);
#endif
#ifdef LFH_RIPEMD320
	REGISTER_HASH(&rmd320_desc);
#endif
#ifdef LFH_WHIRLPOOL
	REGISTER_HASH(&whirlpool_desc);
#endif
#ifdef LFH_BLAKE2S
	REGISTER_HASH(&blake2s_128_desc);
	REGISTER_HASH(&blake2s_160_desc);
	REGISTER_HASH(&blake2s_224_desc);
	REGISTER_HASH(&blake2s_256_desc);
#endif
#ifdef LFH_BLAKE2S
	REGISTER_HASH(&blake2b_160_desc);
	REGISTER_HASH(&blake2b_256_desc);
	REGISTER_HASH(&blake2b_384_desc);
	REGISTER_HASH(&blake2b_512_desc);
#endif
#ifdef LFH_CHC_HASH
	REGISTER_HASH(&chc_desc);
	LFH_ARGCHK(chc_register(find_cipher_any("aes", 8, 16)) == CRYPT_OK);
#endif
	return CRYPT_OK;
}

/**
	@file crypt_register_hash.c
	Register a HASH, Tom St Denis
*/

/**
	Register a hash with the descriptor table
	@param hash   The hash you wish to register
	@return value >= 0 if successfully added (or already present), -1 if unsuccessful
*/
int register_hash(const struct lfh_hash_descriptor *hash)
{
	int x;

	LFH_ARGCHK(hash != NULL);

	LFH_MUTEX_LOCK(&lfh_hash_mutex);
	for (x = 0; x < TAB_SIZE; x++) {
		if (XMEMCMP(&hash_descriptor[x], hash, sizeof(struct lfh_hash_descriptor)) == 0) {
			LFH_MUTEX_UNLOCK(&lfh_hash_mutex);
			return x;
		}
	}

	for (x = 0; x < TAB_SIZE; x++) {
		if (hash_descriptor[x].name == NULL) {
			XMEMCPY(&hash_descriptor[x], hash, sizeof(struct lfh_hash_descriptor));
			LFH_MUTEX_UNLOCK(&lfh_hash_mutex);
			return x;
		}
	}

	LFH_MUTEX_UNLOCK(&lfh_hash_mutex);
	return -1;
}

/**
	@file crypt_unregister_hash.c
	Unregister a hash, Tom St Denis
*/

/**
	Unregister a hash from the descriptor table
	@param hash   The hash descriptor to remove
	@return CRYPT_OK on success
*/
int unregister_hash(const struct lfh_hash_descriptor *hash)
{
	int x;

	LFH_ARGCHK(hash != NULL);

	LFH_MUTEX_LOCK(&lfh_hash_mutex);
	for (x = 0; x < TAB_SIZE; x++) {
		if (XMEMCMP(&hash_descriptor[x], hash, sizeof(struct lfh_hash_descriptor)) == 0) {
			hash_descriptor[x].name = NULL;
			LFH_MUTEX_UNLOCK(&lfh_hash_mutex);
			return CRYPT_OK;
		}
	}
	LFH_MUTEX_UNLOCK(&lfh_hash_mutex);
	return CRYPT_ERROR;
}

/**
	@file zeromem.c
	Zero a block of memory, Tom St Denis
*/

/**
	Zero a block of memory
	@param out    The destination of the area to zero
	@param outlen The length of the area to zero (octets)
*/
void zeromem(volatile void *out, size_t outlen)
{
	volatile char *mem = out;
	LFH_ARGCHKVD(out != NULL);
	while (outlen-- > 0) {
		*mem++ = '\0';
	}
}
