#define OPENSSL_NO_DEPRECATED
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <iostream>
#include <fstream>
#include <fcntl.h>
#include <unistd.h>
#include "aes.hpp"
#include "log.hpp"
#include "stockholm.hpp"
#include "sha.hpp"
#include "rsa.hpp"

// https://www.techbuddies.io/2026/01/17/hands-on-openssl-c-crypto-examples-aes-rsa-hash-and-hmac/#Asymmetric_Encryption_in_C_with_OpenSSL_RSA_Key_Pair_and_Usage

static EVP_PKEY *loadPrivateKey(const char *path)
{
	FILE *fp = fopen(path, "r");
	if (!fp)
	{
		Perror("fopen");
		return NULL;
	}
	EVP_PKEY *pKey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	return pKey; /* NULL on failure */
}

static EVP_PKEY *loadPublicKey(const char *path)
{
	FILE *fp = fopen(path, "r");
	if (!fp)
	{
		Perror("fopen");
		return NULL;
	}
	EVP_PKEY *pKey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
	fclose(fp);
	return pKey; /* NULL on failure */
}

static EVP_PKEY *newRSAKeyPair(void)
{
	EVP_PKEY *pKey = NULL;

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
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
		LogOpenSSLError();
		EVP_PKEY_CTX_free(ctx);
		return (NULL);
	}

	if (EVP_PKEY_keygen(ctx, &pKey) <= 0)
	{
		LogOpenSSLError();
		EVP_PKEY_free(pKey);
		return (NULL);
	}
	EVP_PKEY_CTX_free(ctx);
	return pKey;
}

static int encryptWithKeyPair(const char *path,
							  unsigned char *in,
							  size_t inl,
							  unsigned char *out,
							  size_t *outl)
{
	EVP_PKEY *key = loadPublicKey(path);
	if (!key)
	{
		return (0);
	}
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
	if (EVP_PKEY_encrypt_init(ctx) < 1)
	{
		LogOpenSSLError();
		EVP_PKEY_free(key);
		return (0);
	}

	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) < 1)
	{
		LogOpenSSLError();
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(key);
		return (0);
	}

	if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) < 1)
	{
		LogOpenSSLError();
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(key);
		return (0);
	}

	size_t tmpLen = 0;
	if (EVP_PKEY_encrypt(ctx, NULL, &tmpLen, in, inl) < 1)
	{
		LogOpenSSLError();
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(key);
		return (0);
	}

	if (*outl < tmpLen)
		*outl = tmpLen;

	if (EVP_PKEY_encrypt(ctx, out, &tmpLen, in, inl) < 1)
	{
		LogOpenSSLError();
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(key);
		return (0);
	}

	*outl = tmpLen;
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(key);
	return (1);
}

static int decryptWithKeyPair(const char *path,
							  unsigned char *in,
							  size_t inl,
							  unsigned char *out,
							  size_t *outl)
{
	EVP_PKEY *key = loadPrivateKey(path);
	if (!key)
	{
		return (0);
	}
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
	if (EVP_PKEY_decrypt_init(ctx) < 1)
	{
		LogOpenSSLError();
		EVP_PKEY_free(key);
		return (0);
	}
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) < 1)
	{
		LogOpenSSLError();
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(key);
		return (0);
	}
	if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) < 1)
	{
		LogOpenSSLError();
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(key);
		return (0);
	}
	size_t tmpLen = 0;
	if (EVP_PKEY_decrypt(ctx, NULL, &tmpLen, in, inl) < 1)
	{
		LogOpenSSLError();
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(key);
		return (0);
	}

	if (*outl < tmpLen)
		*outl = tmpLen;
	if (EVP_PKEY_decrypt(ctx, out, &tmpLen, in, inl) < 1)
	{
		LogOpenSSLError();
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(key);
		return (0);
	}

	*outl = tmpLen;
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(key);
	return (1);
}

int EncryptData_HybridRSA_AES(const char *pubkey, BIO *in, BIO *out)
{
	size_t inputLength = BIO_ctrl_pending(in);
	unsigned char *input = new unsigned char[inputLength];
	BIO_read(in, input, inputLength);

	AES_256_CBC cipher = AES_256_CBC::NewCipherWithRandomKey(AES_256_CBC::EncryptionMode);

	int maxEncryptedLen = inputLength + EVP_CIPHER_get_block_size(EVP_aes_256_cbc());
	unsigned char *encrypted = new unsigned char[maxEncryptedLen];

	int updateLen = 0;
	int finalLen = 0;
	cipher.Encrypt(input, inputLength, encrypted, &updateLen);
	cipher.FinishEncryption(encrypted + updateLen, &finalLen);
	int totalEncryptedLen = updateLen + finalLen;
	size_t cipherAesKeyLength = 512;
	unsigned char *cipherAesKey = new unsigned char[cipherAesKeyLength];
	if (!encryptWithKeyPair(pubkey, cipher.GetKey(), 32, cipherAesKey, &cipherAesKeyLength))
	{
		Error("Failed to encrypt file");
		delete[] input;
		delete[] encrypted;
		delete[] cipherAesKey;
		return (0);
	}

	// 4. Build and write header
	stockholm::header *dat = (stockholm::header *)OPENSSL_malloc(sizeof(stockholm::header));
	memset(dat, 0, sizeof(*dat));
	memmove(dat->magic, "STOKOLM!", 8);
	memmove(dat->key, cipherAesKey, cipherAesKeyLength);
	delete[] cipherAesKey;

	dat->cipherSize = totalEncryptedLen;
	dat->rawSize = inputLength;
	sha256(input, inputLength, dat->fileHash);
	delete[] input;

	// 5. Write Header and Encrypted Stream
	BIO_write(out, dat, sizeof(*dat));
	free(dat);
	BIO_write(out, encrypted, totalEncryptedLen);
	delete[] encrypted;

	return (1);
}

int DecryptData_HybridRSA_AES(const char *privkey,
							  stockholm::header *header,
							  BIO *in,
							  BIO *out)
{

	BIO_read(in, header, sizeof(*header));
	unsigned char *input = new unsigned char[header->cipherSize];
	BIO_read(in, input, header->cipherSize);

	unsigned char key[32];
	size_t keyl = 32;
	if (!decryptWithKeyPair(privkey, header->key, 512, key, &keyl))
	{
		Log("Failed to decrypt file");
		delete[] input;
		return (0);
	}
	AES_256_CBC cipher = AES_256_CBC::NewCipherWithKey(key, AES_256_CBC::DecryptionMode);

	unsigned char *aesDecryptionOutput = new unsigned char[header->cipherSize + 16];
	int updateLen = 0;
	int finalLen = 0;

	// 1. Decrypt update
	cipher.Decrypt(input, header->cipherSize, aesDecryptionOutput, &updateLen);
	cipher.FinishDecryption(aesDecryptionOutput + updateLen, &finalLen);
	delete[] input;
	int totalLen = updateLen + finalLen;
	size_t actual;
	BIO_write_ex(out, aesDecryptionOutput, totalLen, &actual);
	delete[] aesDecryptionOutput;
	return (1);
}

int CreateLocalRSAIdentity(fs::path publicPemPath,
						   fs::path localPublicPemPath,
						   fs::path localEncryptedPrivatePemPath)
{
	EVP_PKEY *pKey = newRSAKeyPair();
	if (!pKey)
	{
		Error("Failed to create RSA PKEY");
		return (0);
	}
	BIO *privateKeyMemBIO = BIO_new(BIO_s_mem());
	if (!privateKeyMemBIO)
	{
		LogOpenSSLError();
		EVP_PKEY_free(pKey);
		return (0);
	}
	if (!PEM_write_bio_PrivateKey(privateKeyMemBIO, pKey, NULL, NULL, 0, NULL, NULL))
	{
		LogOpenSSLError();
		EVP_PKEY_free(pKey);
		return (0);
	}
	BIO *encryptedPrivateKeyMemBIO = BIO_new(BIO_s_mem());
	if (!encryptedPrivateKeyMemBIO)
	{
		LogOpenSSLError();
		EVP_PKEY_free(pKey);
		return (0);
	}
	if (!EncryptData_HybridRSA_AES(publicPemPath.c_str(), privateKeyMemBIO, encryptedPrivateKeyMemBIO))
	{
		Error(std::format("Failed to encrypt private key during RSA identity creation"));
		EVP_PKEY_free(pKey);
		return (0);
	}
	BIO_free(privateKeyMemBIO);
	int ret = 1;
	FILE *pubkeyFP = fopen(localPublicPemPath.c_str(), "wb");
	if (pubkeyFP)
	{
		PEM_write_PUBKEY(pubkeyFP, pKey);
		fclose(pubkeyFP);
	}
	else
	{
		Perror("fopen");
		ret = 0;
	}
	if (ret)
	{
		FILE *privkeyFP = fopen(localEncryptedPrivatePemPath.c_str(), "wb");
		if (privkeyFP)
		{
			char buffer[1024];
			size_t len;
			do
			{
				BIO_read_ex(encryptedPrivateKeyMemBIO, buffer, 1024, &len);
				fwrite(buffer, sizeof(char), len, privkeyFP);
			} while (len);
			fclose(privkeyFP);
		}
		else
		{
			Perror("fopen");
			ret = 0;
		}
	}
	EVP_PKEY_free(pKey);
	BIO_free(encryptedPrivateKeyMemBIO);
	return (ret);
}
