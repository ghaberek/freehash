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

#define DOX(x, str) do { \
		fprintf(stderr, "%s - %s: ", #x, (str)); \
		run_cmd((x), __LINE__, __FILE__, #x, (str)); \
	} while (0)

void run_cmd(int res, int line, const char *file, const char *cmd, const char *algo)
{
	if (res != CRYPT_OK) {

		fprintf(stderr, "%s (%d)%s%s\n%s:%d:%s\n", error_to_string(res), res,
			(algo ? " - " : ""), (algo ? algo : ""), file, line, cmd);

		if (res != CRYPT_NOP) {
			exit(EXIT_FAILURE);
		}

	}
	else {
		fprintf(stderr, "OK\n");

	}
}

int main( int argc, char* argv[] )
{
	int x;

	register_all_hashes();

	for (x = 0; hash_descriptor[x].name != NULL; x++) {
		DOX(hash_descriptor[x].test(), hash_descriptor[x].name);
	}

	return 0;
}
