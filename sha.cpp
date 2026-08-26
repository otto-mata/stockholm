
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "log.hpp"
#include "sha.hpp"

int sha256(unsigned char *in, unsigned long inl, unsigned char *out)
{
	EVP_MD_CTX *context = EVP_MD_CTX_new();
	if (!context)
	{
		log(ERR_reason_error_string(ERR_get_error()));
		return (0);
	}

	if (EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1)
	{
		EVP_MD_CTX_free(context);
		log(ERR_reason_error_string(ERR_get_error()));
		return (0);
	}

	if (EVP_DigestUpdate(context, in, inl) != 1)
	{
		EVP_MD_CTX_free(context);
		log(ERR_reason_error_string(ERR_get_error()));
		return (0);
	}

	unsigned int hashLen = 0;
	if (EVP_DigestFinal_ex(context, out, &hashLen) != 1)
	{
		EVP_MD_CTX_free(context);
		log(ERR_reason_error_string(ERR_get_error()));
		return (0);
	}
	EVP_MD_CTX_free(context);
	return (hashLen);
}

bool sha256checksum(unsigned char *in, unsigned long inl, unsigned char *hash)
{
	unsigned char *actual = new unsigned char[SHA256_HASH_LENGTH];
	if (!sha256(in, inl, actual))
		return false;
	bool match = !CRYPTO_memcmp(actual, hash, SHA256_HASH_LENGTH);
	delete[] actual;
	return (match);
}
