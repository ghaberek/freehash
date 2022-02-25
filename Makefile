
CC = gcc$(EXE_EXT)
CFLAGS = -O2 -s

ifeq ($(OS),Windows_NT)
	LIB_EXT = .dll
	EXE_EXT = .exe
else
	LIB_PRE = lib
	LIB_EXT = .so
endif

DOWNLOAD_URL = https://github.com/libtom/libtomcrypt/raw/develop
DOWNLOAD_FILES = \
	src/headers/tomcrypt.h \
	src/headers/tomcrypt_argchk.h \
	src/headers/tomcrypt_cfg.h \
	src/headers/tomcrypt_custom.h \
	src/headers/tomcrypt_hash.h \
	src/headers/tomcrypt_macros.h \
	src/headers/tomcrypt_misc.h \
	src/headers/tomcrypt_private.h \
	src/hashes/md2.c \
	src/hashes/md4.c \
	src/hashes/md5.c \
	src/hashes/sha1.c \
	src/hashes/sha2/sha224.c \
	src/hashes/sha2/sha256.c \
	src/hashes/sha2/sha384.c \
	src/hashes/sha2/sha512.c \
	src/hashes/sha2/sha512_224.c \
	src/hashes/sha2/sha512_256.c \
	src/hashes/sha3.c \
	src/hashes/sha3_test.c \
	src/hashes/helper/hash_file.c \
	src/hashes/helper/hash_filehandle.c \
	src/hashes/helper/hash_memory.c \
	src/hashes/helper/hash_memory_multi.c \
	src/misc/compare_testvector.c \
	src/misc/error_to_string.c \
	src/misc/crypt/crypt_argchk.c \
	src/misc/crypt/crypt_find_hash.c \
	src/misc/crypt/crypt_find_hash_any.c \
	src/misc/crypt/crypt_find_hash_id.c \
	src/misc/crypt/crypt_find_hash_oid.c \
	src/misc/crypt/crypt_hash_descriptor.c \
	src/misc/crypt/crypt_hash_is_valid.c \
	src/misc/crypt/crypt_register_all_hashes.c \
	src/misc/crypt/crypt_register_hash.c \
	src/misc/crypt/crypt_unregister_hash.c \
	src/misc/zeromem.c

source : freehash.h freehash.c

shared : $(LIB_PRE)freehash$(LIB_EXT)

static : $(LIB_PRE)freehash.a

test : test-shared$(EXE_EXT) test-static$(EXE_EXT)

test-shared$(EXE_EXT) : test.c | $(LIB_PRE)freehash$(LIB_EXT)
	$(CC) $(CFLAGS) -o $@ $^ -L. -lfreehash

test-static$(EXE_EXT) : freehash.o test.o
	$(CC) $(CFLAGS) -o $@ $^

freehash.a : freehash.o
	$(AR) rc $@ $^

freehash.c : freehash.h

libfreehash$(LIB_EXT) : freehash.c | freehash.h
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $^

%.o : %.c
	$(CC) $(CFLAGS) -o $@ -c $<

freehash.h : $(DOWNLOAD_FILES)
	$(ECHO)cp src/headers/tomcrypt.h $@
	$(call insert_include,$@,src/headers/tomcrypt_custom.h)
	$(call insert_include,$@,src/headers/tomcrypt_cfg.h)
	$(call insert_include,$@,src/headers/tomcrypt_hash.h)
	$(call insert_include,$@,src/headers/tomcrypt_misc.h)
	$(call insert_string,$@,18,#define LTC_NOTHING)
	$(call insert_string,$@,19,#define LFH_HASH_HELPERS)
	$(call insert_string,$@,20,#define LTC_MD2)
	$(call insert_string,$@,21,#define LTC_MD4)
	$(call insert_string,$@,22,#define LTC_MD5)
	$(call insert_string,$@,23,#define LTC_SHA1)
	$(call insert_string,$@,24,#define LTC_SHA224)
	$(call insert_string,$@,25,#define LTC_SHA256)
	$(call insert_string,$@,26,#define LTC_SHA384)
	$(call insert_string,$@,27,#define LTC_SHA512)
	$(call insert_string,$@,28,#define LTC_SHA512_224)
	$(call insert_string,$@,29,#define LTC_SHA512_256)
	$(call insert_string,$@,30,#define LTC_SHA3)
	$(call insert_license,$@,LICENSE)
	$(call remove_defblock,$@,LTC_NO_CIPHERS)
	$(call remove_defblock,$@,LTC_NO_HASHES)
	$(call remove_defblock,$@,LTC_NO_MACS)
	$(call remove_defblock,$@,LTC_NO_MATH)
	$(call remove_defblock,$@,LTC_NO_MODES)
	$(call remove_defblock,$@,LTC_NO_PKCS)
	$(call remove_defblock,$@,LTC_NO_PRNGS)
	$(call remove_defblock,$@,LTC_NO_MISC)
	$(call remove_comments,$@)
	$(call remove_includes,$@)
	$(call replace_guards,$@)
	$(call replace_macros,$@)
	$(call reduce_spaces,$@)

freehash.c : $(DOWNLOAD_FILES)
	$(ECHO)printf '' > freehash.c
	$(call append_source,$@,src/headers/tomcrypt_argchk.h)
	$(call append_source,$@,src/headers/tomcrypt_macros.h)
	$(call append_private,$@,src/headers/tomcrypt_hash.h)
	$(call append_source,$@,src/hashes/md2.c)
	$(call append_source,$@,src/hashes/md4.c,FF?|GG?|HH?|S[0-9]{2})
	$(call append_source,$@,src/hashes/md5.c,FF?|GG?|HH?|II?)
	$(call append_source,$@,src/hashes/sha1.c,FF?[0123])
	$(call append_source,$@,src/hashes/sha2/sha224.c)
	$(call append_source,$@,src/hashes/sha2/sha256.c,Ch|Maj|S|R|Sigma[01]|Gamma[01])
	$(call append_source,$@,src/hashes/sha2/sha384.c)
	$(call append_source,$@,src/hashes/sha2/sha512.c,Ch|Maj|S|R|Sigma[01]|Gamma[01])
	$(call append_source,$@,src/hashes/sha2/sha512_224.c)
	$(call append_source,$@,src/hashes/sha2/sha512_256.c)
	$(call append_source,$@,src/hashes/sha3.c)
	$(call append_source,$@,src/hashes/sha3_test.c)
	$(call append_source,$@,src/hashes/helper/hash_file.c)
	$(call append_source,$@,src/hashes/helper/hash_filehandle.c)
	$(call append_source,$@,src/hashes/helper/hash_memory.c)
	$(call append_source,$@,src/hashes/helper/hash_memory_multi.c)
	$(call append_source,$@,src/misc/compare_testvector.c)
	$(call append_source,$@,src/misc/error_to_string.c)
	$(call append_source,$@,src/misc/crypt/crypt_argchk.c)
	$(call append_source,$@,src/misc/crypt/crypt_find_hash.c)
	$(call append_source,$@,src/misc/crypt/crypt_find_hash_any.c)
	$(call append_source,$@,src/misc/crypt/crypt_find_hash_id.c)
	$(call append_source,$@,src/misc/crypt/crypt_find_hash_oid.c)
	$(call append_source,$@,src/misc/crypt/crypt_hash_descriptor.c)
	$(call append_source,$@,src/misc/crypt/crypt_hash_is_valid.c)
	$(call append_source,$@,src/misc/crypt/crypt_register_all_hashes.c)
	$(call append_source,$@,src/misc/crypt/crypt_register_hash.c)
	$(call append_source,$@,src/misc/crypt/crypt_unregister_hash.c)
	$(call append_source,$@,src/misc/zeromem.c)
	$(call insert_string,$@,1,#include "freehash.h")
	$(call insert_string,$@,1,)
	$(call insert_license,$@,LICENSE)
	$(call remove_comments,$@)
	$(call remove_includes,$@)
	$(call replace_guards,$@)
	$(call replace_macros,$@)
	$(call reduce_spaces,$@)

src/% : 
	$(ECHO)mkdir -p $(dir $@)
	$(ECHO)wget -q "$(DOWNLOAD_URL)/$@" -O "$@"

clean :
	-@rm -f freehash.o freehash.a $(LIB_PRE)freehash$(LIB_EXT)
	-@rm -f test.o test-static$(EXE_EXT) test-shared$(EXE_EXT)

distclean : clean
	-@rm -f $(DOWNLOAD_FILES)
	-@rmdir -p src/headers
	-@rmdir -p src/hashes/helper
	-@rmdir -p src/hashes/sha2
	-@rmdir -p src/misc/crypt

.PHONY : all clean distclean source shared static test

ifneq ($(VERBOSE),1)
ECHO = @
endif

##
## Extract the block of code from the source file between "/* [filename] */" and the next "/* ... */"
## and append it to the target file.
##
## $(1): Target file name
## $(2): Search file name
##
define append_private =
$(ECHO)sed -En '/^\/\* $(notdir $(2)) \*\//,/^\/\* \w+\.h \*\//p' $(dir $(2))/tomcrypt_private.h | head -n-1 >> $(1)
endef

##
## Append the contents of the source file, apply an optional prefix, and append it to the target file.
##
## Note: Anything matched by the optional pattern will be prefixed with the base name and an underscore.
##
## $(1): Target file name
## $(2): Source file name
## $(3): Pattern to prefix
##
define append_source =
$(ECHO)$(if $(3),sed -E 's/\b($(3))\b/$(patsubst %.c,%,$(notdir $2))_\1/g',cat) $(2) >> $(1)
endef

##
## Insert a commented block at the top of a file.
##
## $(1): Target file name
## $(2): Source file name
##
define insert_license =
$(ECHO)sed -Ei '1 a */' $(1)
$(ECHO)sed -Ei '1 r $(2)' $(1)
$(ECHO)sed -Ei '1 a /*' $(1)
endef

##
## Replace an include line with the contents of the file it specifies.
##
## $(1): Target file name
## $(2): Include file name
##
define insert_include =
$(ECHO)sed -Ei 's/^#include "($(notdir $(2)))"/cat $(subst /,\/,$(dir $(2)))\/\1/e' $(1)
endef

##
## Insert a raw string into the target file.
##
## $(1): Target file name
## $(2): Line number to insert at
## $(3): Content to insert (optional)
##
define insert_string =
$(ECHO)sed -Ei '$(2) a $(if $(3),$(3),\\n)' $(1)
endef

##
## Reduce leading spaces into tabs within a file and remove multiple chunks of empty lines.
##
## $(1): Target file name
##
define reduce_spaces =
$(ECHO)sed -Ei ':a;s/^(\t*)([ ]{4}|[ ]{3}|[ ]{2})/\1\t/;ta' $(1); sed -Ei 's/[ ]+[\]$$/ \\/g' $(1)
$(ECHO)sed -Ei '/^$$/N;/^\n$$/D' $(1)
endef

##
## Remove lines that are only comments.
##
## $(1): Target file name
##
define remove_comments =
$(ECHO)sed -Ei '/^\s*\/\* .+ \*\/$$/d' $(1)
endef

##
## Remove blocks contained in #ifndef [name] ... #endif /* [name] */.
##
## $(1): Target file name
## $(2): ifdef block name
##
define remove_defblock =
$(ECHO)sed -Ei '/^#ifndef $(2)/,/^#endif \/\* $(2) \*\//d' $(1)
endef

##
## Remove any extraneous include statements.
##
## $(1): Target file name
##
define remove_includes =
$(ECHO)sed -Ei '/^#include "tomcrypt_\w+\.h"/d' $(1)
endef

##
## Replace include guards ifdefs with our own name.
##
## $(1): Target file name
##
define replace_guards =
$(ECHO)sed -Ei 's/TOMCRYPT_(\w+)?H(_?)/FREEHASH_\1H\2/g' $(1)
endef

##
## Replace all libtomcrypt "LFH" macros with our own "LFH" macro.
##
## $(1): Target file name
##
define replace_macros =
$(ECHO)sed -Ei 's/ltc_(\w+)/lfh_\1/g' $(1)
$(ECHO)sed -Ei 's/LTC_(\w+)/LFH_\1/g' $(1)
endef
