
namespace freehash

include std/dll.e
include std/machine.e
include std/types.e

ifdef WINDOWS then
atom freehash = open_dll( "freehash.dll" )
elsifdef LINUX then
atom freehash = open_dll( "libfreehash.so" )
end ifdef

constant
	_hash_descriptor     = define_c_var( freehash, "hash_descriptor" ),
	_md2_init            = define_c_func( freehash, "+md2_init", {C_POINTER}, C_INT ),
	_md2_process         = define_c_func( freehash, "+md2_process", {C_POINTER,C_POINTER,C_ULONG}, C_INT ),
	_md2_done            = define_c_func( freehash, "+md2_done", {C_POINTER,C_POINTER}, C_INT ),
	_md4_init            = define_c_func( freehash, "+md4_init", {C_POINTER}, C_INT ),
	_md4_process         = define_c_func( freehash, "+md4_process", {C_POINTER,C_POINTER,C_ULONG}, C_INT ),
	_md4_done            = define_c_func( freehash, "+md4_done", {C_POINTER,C_POINTER}, C_INT ),
	_md5_init            = define_c_func( freehash, "+md5_init", {C_POINTER}, C_INT ),
	_md5_process         = define_c_func( freehash, "+md5_process", {C_POINTER,C_POINTER,C_ULONG}, C_INT ),
	_md5_done            = define_c_func( freehash, "+md5_done", {C_POINTER,C_POINTER}, C_INT ),
	_sha1_init           = define_c_func( freehash, "+sha1_init", {C_POINTER}, C_INT ),
	_sha1_process        = define_c_func( freehash, "+sha1_process", {C_POINTER,C_POINTER,C_ULONG}, C_INT ),
	_sha1_done           = define_c_func( freehash, "+sha1_done", {C_POINTER,C_POINTER}, C_INT ),
	_sha224_init         = define_c_func( freehash, "+sha224_init", {C_POINTER}, C_INT ),
	_sha224_done         = define_c_func( freehash, "+sha224_done", {C_POINTER,C_POINTER}, C_INT ),
	_sha256_init         = define_c_func( freehash, "+sha256_init", {C_POINTER}, C_INT ),
	_sha256_done         = define_c_func( freehash, "+sha256_done", {C_POINTER,C_POINTER}, C_INT ),
	_sha256_process      = define_c_func( freehash, "+sha256_process", {C_POINTER,C_POINTER,C_ULONG}, C_INT ),
	_sha384_init         = define_c_func( freehash, "+sha384_init", {C_POINTER}, C_INT ),
	_sha384_done         = define_c_func( freehash, "+sha384_done", {C_POINTER,C_POINTER}, C_INT ),
	_sha512_init         = define_c_func( freehash, "+sha512_init", {C_POINTER}, C_INT ),
	_sha512_done         = define_c_func( freehash, "+sha512_done", {C_POINTER,C_POINTER}, C_INT ),
	_sha512_process      = define_c_func( freehash, "+sha512_process", {C_POINTER,C_POINTER,C_ULONG}, C_INT ),
	_sha512_224_done     = define_c_func( freehash, "+sha512_224_done", {C_POINTER,C_POINTER}, C_INT ),
	_sha512_224_init     = define_c_func( freehash, "+sha512_224_init", {C_POINTER}, C_INT ),
	_sha512_256_done     = define_c_func( freehash, "+sha512_256_done", {C_POINTER,C_POINTER}, C_INT ),
	_sha512_256_init     = define_c_func( freehash, "+sha512_256_init", {C_POINTER}, C_INT ),
	_sha3_224_init       = define_c_func( freehash, "+sha3_224_init", {C_POINTER}, C_INT ),
	_sha3_256_init       = define_c_func( freehash, "+sha3_256_init", {C_POINTER}, C_INT ),
	_sha3_384_init       = define_c_func( freehash, "+sha3_384_init", {C_POINTER}, C_INT ),
	_sha3_512_init       = define_c_func( freehash, "+sha3_512_init", {C_POINTER}, C_INT ),
	_sha3_process        = define_c_func( freehash, "+sha3_process", {C_POINTER,C_POINTER,C_ULONG}, C_INT ),
	_sha3_done           = define_c_func( freehash, "+sha3_done", {C_POINTER,C_POINTER}, C_INT ),
	_sha3_shake_init     = define_c_func( freehash, "+sha3_shake_init", {C_POINTER,C_INT}, C_INT ),
	_sha3_shake_done     = define_c_func( freehash, "+sha3_shake_done", {C_POINTER,C_POINTER,C_ULONG}, C_INT ),
	_sha3_shake_memory   = define_c_func( freehash, "+sha3_shake_memory", {C_INT,C_POINTER,C_ULONG,C_POINTER,C_POINTER}, C_INT ),
	_find_hash           = define_c_func( freehash, "+find_hash", {C_POINTER}, C_INT ),
	_find_hash_id        = define_c_func( freehash, "+find_hash_id", {C_UCHAR}, C_INT ),
	_find_hash_oid       = define_c_func( freehash, "+find_hash_oid", {C_POINTER,C_ULONG}, C_INT ),
	_find_hash_any       = define_c_func( freehash, "+find_hash_any", {C_POINTER,C_INT}, C_INT ),
	_register_hash       = define_c_func( freehash, "+register_hash", {C_POINTER}, C_INT ),
	_unregister_hash     = define_c_func( freehash, "+unregister_hash", {C_POINTER}, C_INT ),
	_register_all_hashes = define_c_func( freehash, "+register_all_hashes", {}, C_INT ),
	_hash_is_valid       = define_c_func( freehash, "+hash_is_valid", {C_INT}, C_INT ),
	_hash_memory         = define_c_func( freehash, "+hash_memory", {C_INT,C_POINTER,C_ULONG,C_POINTER,C_POINTER}, C_INT ),
	_hash_file           = define_c_func( freehash, "+hash_file", {C_INT,C_POINTER,C_POINTER,C_POINTER}, C_INT ),
$

public enum
	CRYPT_OK=0,
	CRYPT_ERROR,
	CRYPT_NOP,
	CRYPT_INVALID_KEYSIZE,
	CRYPT_INVALID_ROUNDS,
	CRYPT_FAIL_TESTVECTOR,
	CRYPT_BUFFER_OVERFLOW,
	CRYPT_INVALID_PACKET,
	CRYPT_INVALID_PRNGSIZE,
	CRYPT_ERROR_READPRNG,
	CRYPT_INVALID_CIPHER,
	CRYPT_INVALID_HASH,
	CRYPT_INVALID_PRNG,
	CRYPT_MEM,
	CRYPT_PK_TYPE_MISMATCH,
	CRYPT_PK_NOT_PRIVATE,
	CRYPT_INVALID_ARG,
	CRYPT_FILE_NOTFOUND,
	CRYPT_PK_INVALID_TYPE,
	CRYPT_OVERFLOW,
	CRYPT_PK_ASN1_ERROR,
	CRYPT_INPUT_TOO_LONG,
	CRYPT_PK_INVALID_SIZE,
	CRYPT_INVALID_PRIME_SIZE,
	CRYPT_PK_INVALID_PADDING,
	CRYPT_HASH_OVERFLOW

constant SIZEOF_HASH_STATE = 416

function _init( integer func )
	atom md = allocate_data( SIZEOF_HASH_STATE, TRUE )
	if c_func( func, {md} ) != CRYPT_OK then
		return NULL
	end if
	return md
end function

function _proc( integer func, atom md, sequence in, integer inlen )
	atom ptr = allocate_data( inlen, TRUE )
	poke( ptr, in )
	return c_func( func, {md,ptr,inlen} )
end function

function _done( integer func, atom md, integer outlen )
	atom ptr = allocate_data( outlen, TRUE )
	mem_set( ptr, NULL, outlen )
	if c_func( func, {md,ptr} ) != CRYPT_OK then
		return {}
	end if
	return peek({ ptr, outlen })
end function

public function md2_init()
	return _init( _md2_init )
end function

public function md2_process( atom md, sequence in )
	return _proc( _md2_process, md, in, length(in) )
end function

public function md2_done( atom md )
	return _done( _md2_done, md, 16 )
end function

public function md4_init()
	return _init( _md4_init )
end function

public function md4_process( atom md, sequence in )
	return _proc( _md4_process, md, in, length(in) )
end function

public function md4_done( atom md )
	return _done( _md4_done, md, 16 )
end function

public function md5_init()
	return _init( _md5_init )
end function

public function md5_process( atom md, sequence in )
	return _proc( _md5_process, md, in, length(in) )
end function

public function md5_done( atom md )
	return _done( _md5_done, md, 16 )
end function

public function sha1_init()
	return _init( _sha1_init )
end function

public function sha1_process( atom md, sequence in )
	return _proc( _sha1_process, md, in, length(in) )
end function

public function sha1_done( atom md )
	return _done( _sha1_done, md, 20 )
end function

public function sha224_init()
	return _init( _sha224_init )
end function

public function sha224_process( atom md, sequence in )
	return _proc( _sha256_process, md, in, length(in) )
end function

public function sha224_done( atom md )
	return _done( _sha224_done, md, 28 )
end function

public function sha256_init()
	return _init( _sha256_init )
end function

public function sha256_process( atom md, sequence in )
	return _proc( _sha256_process, md, in, length(in) )
end function

public function sha256_done( atom md )
	return _done( _sha256_done, md, 32 )
end function

public function sha384_init()
	return _init( _sha384_init )
end function

public function sha384_process( atom md, sequence in )
	return _proc( _sha512_process, md, in, length(in) )
end function

public function sha384_done( atom md )
	return _done( _sha384_done, md, 48 )
end function

public function sha512_init()
	return _init( _sha512_init )
end function

public function sha512_process( atom md, sequence in )
	return _proc( _sha512_process, md, in, length(in) )
end function

public function sha512_done( atom md )
	return _done( _sha512_done, md, 64 )
end function

public function sha512_224_init()
	return _init( _sha512_224_init )
end function

public function sha512_224_process( atom md, sequence in )
	return _proc( _sha512_process, md, in, length(in) )
end function

public function sha512_224_done( atom md )
	return _done( _sha512_224_done, md, 28 )
end function

public function sha512_256_init()
	return _init( _sha512_256_init )
end function

public function sha512_256_process( atom md, sequence in )
	return _proc( _sha512_process, md, in, length(in) )
end function

public function sha512_256_done( atom md )
	return _done( _sha512_256_done, md, 32 )
end function

public function sha3_224_init()
	return _init( _sha3_224_init )
end function

public function sha3_256_init()
	return _init( _sha3_256_init )
end function

public function sha3_384_init()
	return _init( _sha3_384_init )
end function

public function sha3_512_init()
	return _init( _sha3_512_init )
end function

public function sha3_process( atom md, sequence in )
	return _proc( _sha3_process, md, in, length(in) )
end function

constant SHA3_CAPACITY_WORDS = 412

public function sha3_done( atom md )
	return _done( _sha3_done, md, peek2u(md+SHA3_CAPACITY_WORDS)*4 )
end function

public function find_hash( sequence name )
	register_all_hashes()
	return c_func( _find_hash, {allocate_string(name,TRUE)} )
end function

public function find_hash_id( integer id )
	register_all_hashes()
	return c_func( _find_hash_id, {id} )
end function

public function find_hash_oid( sequence oid )
	register_all_hashes()
	atom ptr = allocate_data( sizeof(C_ULONG)*length(oid), TRUE )
	poke_long( ptr, oid )
	return c_func( _find_hash_oid, {ptr,length(oid)} )
end function

public function find_hash_any( sequence name, integer digestlen )
	register_all_hashes()
	return c_func( _find_hash_any, {allocate_string(name,TRUE),digestlen} )
end function

public function register_hash( atom ptr )
	return c_func( _register_hash, {ptr} )
end function

public function unregister_hash( atom ptr )
	return c_func( _unregister_hash, {ptr} )
end function

public function register_all_hashes()
	if peek_pointer( _hash_descriptor ) = NULL then
		return c_func( _register_all_hashes, {} )
	end if
	return CRYPT_OK
end function

public function hash_is_valid( integer idx )
	return c_func( _hash_is_valid, {idx} )
end function

public function hash_memory( object idx, sequence in )

	if sequence( idx ) then
		idx = find_hash( idx )
	end if

	integer inlen = length( in )
	atom pin = allocate_data( inlen, TRUE )
	poke( pin, in )

	atom outlen = 64
	atom pout = allocate_data( outlen, TRUE )
	atom poutlen = allocate_data( sizeof(C_ULONG), TRUE )
	poke( poutlen, outlen )

	if c_func( _hash_memory, {idx,pin,inlen,pout,poutlen} ) != CRYPT_OK then
		return {}
	end if

	outlen = peek_longu( poutlen )

	return peek({ pout, outlen })
end function

public function hash_file( object idx, sequence fname )

	if sequence( idx ) then
		idx = find_hash( idx )
	end if

	atom outlen = 64
	atom pout = allocate_data( outlen, TRUE )
	atom poutlen = allocate_data( sizeof(C_ULONG), TRUE )
	poke( poutlen, outlen )

	if c_func( _hash_file, {idx,allocate_string(fname,TRUE),pout,poutlen} ) != CRYPT_OK then
		return {}
	end if

	outlen = peek_longu( poutlen )

	return peek({ pout, outlen })
end function
