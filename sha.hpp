#pragma once
#define SHA256_HASH_LENGTH 32

int sha256(unsigned char *in, unsigned long inl, unsigned char *out);
bool sha256checksum(unsigned char *in, unsigned long inl, unsigned char *hash);
