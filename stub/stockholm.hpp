#include <cstring>
#include <filesystem>
#include "opts.hpp"

namespace stockholm
{
	typedef struct stockholm_header_st header;
	struct stockholm_header_st
	{
		unsigned char magic[8];
		unsigned char key[1024];
		unsigned char fileHash[32];
		unsigned long cipherSize;
		unsigned long rawSize;
	} __attribute__((packed));
	extern const char *extensions[];
	extern const unsigned long extensions_count;
	extern const char *localPrivateKeyFileName;
	extern const char *localPublicKeyFileName;
	extern opts options;
} // namespace stockholm

#pragma once
