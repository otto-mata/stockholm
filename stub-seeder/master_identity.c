#include <openssl/err.h>
#include <openssl/evp.h>

static EVP_PKEY	*new_rsa(void)
{
	EVP_PKEY		*pKey;
	EVP_PKEY_CTX	*ctx;

	pKey = NULL;
	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (ctx == NULL)
	{
		LogOpenSSLError();
		return (NULL);
	}
	if (EVP_PKEY_keygen_init(ctx) < 1)
	{
		LogOpenSSLError();
		EVP_PKEY_CTX_free(ctx);
		return (NULL);
	}
	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 4096) <= 0)
	{
		EVP_PKEY_CTX_free(ctx);
		return (NULL);
	}
	if (EVP_PKEY_keygen(ctx, &pKey) <= 0)
	{
		EVP_PKEY_free(pKey);
		EVP_PKEY_CTX_free(ctx);
		return (NULL);
	}
	EVP_PKEY_CTX_free(ctx);
	return (pKey);
}
