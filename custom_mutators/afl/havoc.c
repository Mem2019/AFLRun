#include "types.h"
#include "config.h"
#include "debug.h"
#include "alloc-inl.h"

#include <stdio.h>
#include <stdbool.h>

void *afl_custom_init(void* p, unsigned int s);
void afl_custom_deinit(void* p);
size_t afl_custom_fuzz(void *data, u8 *buf, size_t buf_size, u8 **out_buf,
						u8 *add_buf, size_t add_buf_size, size_t max_size);

u8* buf; long size;
bool read_seed(const char* file)
{
	FILE* f = fopen(file, "rb");
	if (f == NULL)
	{
		perror("fopen failed");
		return false;
	}
	int r = fseek(f, 0, SEEK_END);
	if (r != 0)
	{
		perror("fseek failed");
		return false;
	}
	size = ftell(f);
	if (size < 0)
	{
		perror("ftell failed");
		return false;
	}
	r = fseek(f, 0, SEEK_SET);
	if (r != 0)
	{
		perror("fseek failed");
		return false;
	}
	buf = malloc(size);
	if (fread(buf, 1, size, f) != size)
	{
		perror("fread failed");
		return false;
	}
	fclose(f);
	return true;
}

int main(int argc, char const *argv[])
{
	if (argc < 4)
	{
		fprintf(stderr, "Usage: havoc seed times outdir [-x dict]\n");
		return 1;
	}
	afl_custom_init(NULL, 0);
	if (!read_seed(argv[1]))
		return 1;
	size_t times = strtoul(argv[2], NULL, 10);
	for (size_t i = 0; i < times; ++i)
	{
		u8* out_buf;
		size_t out_len = afl_custom_fuzz(
			NULL, buf, size, &out_buf, buf, size, MAX_FILE);
		u8* out_file = alloc_printf("%s/id:%.6lu.bin", argv[3], i);

		FILE* f = fopen(out_file, "wb");
		if (f == NULL)
		{
			perror("fopen failed");
			return 1;
		}
		if (fwrite(out_buf, 1, out_len, f) != out_len)
		{
			perror("fwrite failed");
			return 1;
		}
		if (fclose(f))
		{
			perror("fclose failed");
			return 1;
		}
		ck_free(out_file);
	}
	afl_custom_deinit(NULL);
	return 0;
}