#include <openssl/bio.h>
#include <openssl/pem.h>
#include "log.hpp"

namespace
{
	BIO *newBIOFromData(const unsigned char *data, size_t dataSize)
	{
		BIO *bio = BIO_new(BIO_s_mem());
		if (bio)
			BIO_write(bio, data, dataSize);
		else
			LogOpenSSLError();
		return (bio);
	}
}

EVP_PKEY *NewPublicKey(const unsigned char *data)
{
	EVP_PKEY *pub = NULL;
	BIO *bio = newBIOFromData(data, strlen((const char *)data));
	if (bio)
	{
		pub = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
		if (!pub)
			LogOpenSSLError();
	}
	else
		LogOpenSSLError();
	return (pub);
}
