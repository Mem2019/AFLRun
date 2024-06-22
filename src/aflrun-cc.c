#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "debug.h"
#include "alloc-inl.h"

/* This compiler is used to handle cases where we cannot designate compiler
via $CC and $CXX, but instead we can only replace their compiler with the AFL one.
For example, when compiling chroimium/v8. */

int main(int argc, char const *argv[])
{
	char const** new_argv = (char const**)malloc((argc + 1) * sizeof(char*));

	char* afl_path = getenv("AFL_PATH");
	if (afl_path == NULL)
		FATAL("Please specify AFL_PATH");

	new_argv[0] = alloc_printf("%s/%s", afl_path,
		strstr(argv[0], "++") == NULL ? "afl-clang-lto" : "afl-clang-lto++");
	for (int i = 1; i < argc; ++i)
		new_argv[i] = argv[i];
	new_argv[argc] = NULL;

	execvp(new_argv[0], (char**)new_argv);

	return 0;
}
