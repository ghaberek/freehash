# freehash

freehash is a single file library of common message hashing functions. This project is inspired
by [picohash][2] but aims to include more common hash functions and to be more easily reproducable
so as to stay up to date with the upstream source ([libtomcrypt][1]) as necessary.

## Usage

Simply copy the source files ([freehash.h](freehash.h)/[freehash.c](freehash.c)) into your project.
You can use any of the hash functions straight away or call `register_all_hashes()` and enumerate
them by looping through `hash_descriptor[]` or by calling `find_hash()`, etc.

    for (int i = 0; hash_descriptor[i].name != NULL; i++) {
        printf("%s\n", hash_descriptor[i].name);
    }

The following hash fucntions are enabled by default:

    md2
    md4
    md5
    sha1
    sha224
    sha256
    sha384
    sha512
    sha512-224
    sha512-256
    sha3-224
    sha3-256
    sha3-384
    sha3-512

## Building

You can rebuild the source files by running `make`. The Makefile will fetch the required upstream
sources using `wget` and then amalgamate them with an unhealthy amount of `sed` commands. (And if
you're really curious, you can run `make VERBOSE=1` to see all of the commands it's using.)

**Note:** the Makefile is not required for building freehash. You can compile it right away:

    gcc -o freehash.o -c freehash.c

### Targets

- `make clean` - remove generated build files
- `make distclean` - remove generated build files and downloaded upstream sources
- `make sources` - rebuild `freehash.h` and `freehash.c` (this is the default `make` target)
- `make shared` - build the shared library `libfreehash.so` or `freehash.dll`
- `make static` - build the static library `freehash.a`
- `make test` - build and run the shared and static test applications

### Options

- `VERBOSE=1` - enable verbose output to see all of the `sed` and `wget` commands

## Testing

Running `make test` will produce two test files: `test-shared` which links to `libfreehash.so` and
`test-static` which links directly with `freehash.o`. Running these should produce an `"OK"` output
for each of the hash functions listed above.

## License

As with [libtomcrypt][1], this project is released as public domain under [Unlicense][3].

[1]: https://github.com/libtom/libtomcrypt
[2]: https://github.com/kazuho/picohash
[3]: https://unlicense.org/
