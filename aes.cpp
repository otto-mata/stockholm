#include "aes.hpp"
#include "log.hpp"
#include <cstring>
#include <iostream>

AES_256_CBC::AES_256_CBC(unsigned char *_key, unsigned char *_iv, MODE _mode)
{
	memcpy(key, _key, sizeof(key));
	memcpy(iv, _iv, sizeof(iv));
	mode = _mode;
	init = false;
	error = false;
	ctx = EVP_CIPHER_CTX_new();
	cipher = EVP_aes_256_cbc();
	if (!ctx || !cipher)
	{
		log(ERR_reason_error_string(ERR_get_error()));
		error = true;
		EVP_CIPHER_CTX_free(ctx);
		return;
	}
}

AES_256_CBC::~AES_256_CBC()
{
	EVP_CIPHER_CTX_free(ctx);
}

void AES_256_CBC::Init()
{
	switch (mode)
	{
	case DecryptionMode:
		initDecryption();
		break;
	case EncryptionMode:
		initEncryption();
		break;
	default:
		error = true;
		break;
	}
}

void AES_256_CBC::Decrypt(unsigned char *in, int inl, unsigned char *out,
						  int *outl)
{
	int outlen;

	if (mode != DecryptionMode)
		error = true;
	if (error)
		return;
	if (!EVP_DecryptUpdate(ctx, out, outl, in, inl))
	{
		log(ERR_reason_error_string(ERR_get_error()));
		error = true;
		return;
	}
}

void AES_256_CBC::FinishDecryption(unsigned char *out, int *outl)
{
	int tmplen;

	if (mode != DecryptionMode)
		error = true;
	if (error)
		return;
	if (!EVP_DecryptFinal_ex(ctx, (unsigned char *)((uintptr_t)out + *outl),
							 &tmplen))
	{
		log(ERR_reason_error_string(ERR_get_error()));
		error = true;
		return;
	}
	*outl += tmplen;
}

void AES_256_CBC::Encrypt(unsigned char *in, int inl, unsigned char *out,
						  int *outl)
{
	if (mode != EncryptionMode)
		error = true;
	if (error)
		return;
	if (!EVP_EncryptUpdate(ctx, out, outl, in, inl))
	{
		log(ERR_reason_error_string(ERR_get_error()));
		error = true;
		return;
	}
}

void AES_256_CBC::FinishEncryption(unsigned char *out, int *outl)
{
	int tmplen;

	if (mode != EncryptionMode)
		error = true;
	if (error)
		return;
	if (!EVP_EncryptFinal_ex(ctx, (unsigned char *)((uintptr_t)out + *outl),
							 &tmplen))
	{
		log(ERR_reason_error_string(ERR_get_error()));
		error = true;
		return;
	}
	*outl += tmplen;
}

AES_256_CBC AES_256_CBC::NewCipherWithRandomKey(MODE _mode)
{
	unsigned char key[32];
	unsigned char iv[16] = {0};

	RAND_bytes(key, 32);
	auto instance = AES_256_CBC(key, iv, _mode);
	instance.Init();
	return (instance);
}

AES_256_CBC AES_256_CBC::NewCipherWithKey(unsigned char *key, MODE _mode)
{
	unsigned char iv[16] = {0};

	auto instance = AES_256_CBC(key, iv, _mode);
	instance.Init();
	return (instance);
}

size_t AES_256_CBC::SizeOfCipher(size_t clear_size)
{
	return (clear_size + EVP_CIPHER_get_block_size(EVP_aes_256_cbc()) -
			(clear_size % EVP_CIPHER_get_block_size(EVP_aes_256_cbc())));
}

unsigned char *AES_256_CBC::GetKey(void)
{
	return (key);
}

void AES_256_CBC::initEncryption()
{
	if (!EVP_EncryptInit_ex2(ctx, cipher, key, iv, nullptr))
	{
		log(ERR_reason_error_string(ERR_get_error()));
		error = true;
		return;
	}
}

void AES_256_CBC::initDecryption()
{
	if (!EVP_DecryptInit_ex2(ctx, cipher, key, iv, nullptr))
	{
		log(ERR_reason_error_string(ERR_get_error()));
		error = true;
		return;
	}
}
