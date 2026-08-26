#include <cstring>
namespace stockholm
{
	typedef struct stockholm_header_st header;
	struct stockholm_header_st
	{
		unsigned char magic[8];
		unsigned char key[1024];
		unsigned char file_hash[32];
		unsigned long content_size;
	};
	extern const char *extensions[];
	extern const unsigned long extensions_count;
} // namespace stockholm

#pragma once
