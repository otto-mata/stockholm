
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "log.hpp"

void sha256(unsigned char *in, unsigned long inl, unsigned char *out)
{
	EVP_MD_CTX *context = EVP_MD_CTX_new();
	if (!context)
	{
		log(ERR_reason_error_string(ERR_get_error()));
		return;
	}

	if (EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1)
	{
		EVP_MD_CTX_free(context);
		log(ERR_reason_error_string(ERR_get_error()));
		return;
	}

	if (EVP_DigestUpdate(context, in, inl) != 1)
	{
		EVP_MD_CTX_free(context);
		log(ERR_reason_error_string(ERR_get_error()));
		return;
	}

	unsigned int hashLen = 0;
	if (EVP_DigestFinal_ex(context, out, &hashLen) != 1)
	{
		EVP_MD_CTX_free(context);
		log(ERR_reason_error_string(ERR_get_error()));
		return;
	}
	EVP_MD_CTX_free(context);
}
