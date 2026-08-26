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

static EVP_PKEY *load_private_key(const char *path)
{
	FILE *fp = fopen(path, "r");
	if (!fp)
		return NULL;
	EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	return pkey; /* NULL on failure */
}

static EVP_PKEY *load_public_key(const char *path)
{
	FILE *fp = fopen(path, "r");
	if (!fp)
		return NULL;
	EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
	fclose(fp);
	return pkey; /* NULL on failure */
}

static EVP_PKEY *new_rsa(void)
{
	EVP_PKEY *pkey = NULL;

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

	if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
	{
		LogOpenSSLError();
		EVP_PKEY_free(pkey);
		return (NULL);
	}
	EVP_PKEY_CTX_free(ctx);
	return pkey;
}

static int pkey_encrypt(const char *path,
						unsigned char *in,
						size_t inl,
						unsigned char *out,
						size_t *outl)
{
	// PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);
	// PEM_write_PUBKEY(stdout, pkey);

	EVP_PKEY *pub_key = load_public_key(path);
	EVP_PKEY_CTX *enc_ctx = EVP_PKEY_CTX_new(pub_key, NULL);
	if (EVP_PKEY_encrypt_init(enc_ctx) < 1)
	{
		LogOpenSSLError();
		return (0);
	}

	if (EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_OAEP_PADDING) < 1)
	{
		LogOpenSSLError();
		EVP_PKEY_CTX_free(enc_ctx);
		return (0);
	}

	if (EVP_PKEY_CTX_set_rsa_oaep_md(enc_ctx, EVP_sha256()) < 1)
	{
		LogOpenSSLError();
		EVP_PKEY_CTX_free(enc_ctx);
		return (0);
	}

	size_t tmp_len = 0;
	if (EVP_PKEY_encrypt(enc_ctx, NULL, &tmp_len, in, inl) < 1)
	{
		LogOpenSSLError();
		EVP_PKEY_CTX_free(enc_ctx);
		return (0);
	}

	if (*outl < tmp_len)
		*outl = tmp_len;

	if (EVP_PKEY_encrypt(enc_ctx, out, &tmp_len, in, inl) < 1)
	{
		LogOpenSSLError();
		EVP_PKEY_CTX_free(enc_ctx);
		return (0);
	}

	*outl = tmp_len;
	EVP_PKEY_CTX_free(enc_ctx);
	return (1);
}

static int pkey_decrypt(const char *path,
						unsigned char *in,
						size_t inl,
						unsigned char *out,
						size_t *outl)
{
	EVP_PKEY *priv_key = load_private_key(path);
	EVP_PKEY_CTX *dec_ctx = EVP_PKEY_CTX_new(priv_key, NULL);
	if (EVP_PKEY_decrypt_init(dec_ctx) < 1)
	{
		LogOpenSSLError();
		return (0);
	}
	if (EVP_PKEY_CTX_set_rsa_padding(dec_ctx, RSA_PKCS1_OAEP_PADDING) < 1)
	{
		LogOpenSSLError();
		EVP_PKEY_CTX_free(dec_ctx);
		return (0);
	}
	if (EVP_PKEY_CTX_set_rsa_oaep_md(dec_ctx, EVP_sha256()) < 1)
	{
		LogOpenSSLError();
		EVP_PKEY_CTX_free(dec_ctx);
		return (0);
	}
	size_t tmp_len = 0;
	if (EVP_PKEY_decrypt(dec_ctx, NULL, &tmp_len, in, inl) < 1)
	{
		LogOpenSSLError();
		EVP_PKEY_CTX_free(dec_ctx);
		return (0);
	}

	if (*outl < tmp_len)
		*outl = tmp_len;
	if (EVP_PKEY_decrypt(dec_ctx, out, &tmp_len, in, inl) < 1)
	{
		LogOpenSSLError();
		EVP_PKEY_CTX_free(dec_ctx);
		return (0);
	}

	*outl = tmp_len;
	EVP_PKEY_CTX_free(dec_ctx);
	return (1);
}

int rsa_aes_hybrid_encryption(const char *pubkey,
							  const char *outfile,
							  unsigned char *in,
							  size_t inl)
{

	// Encrypt with AES 256 CBC, random key
	AES_256_CBC cipher = AES_256_CBC::NewCipherWithRandomKey(AES_256_CBC::EncryptionMode);

	const size_t dataSize = 16;
	size_t sizeOfBuffer = AES_256_CBC::SizeOfCipher(dataSize);
	int bufferl = (int)sizeOfBuffer;
	unsigned char *buffer = (unsigned char *)OPENSSL_malloc(sizeOfBuffer);
	std::basic_string<unsigned char> bufferAcc = std::basic_string<unsigned char>();
	bufferAcc.clear();
	size_t processed = 0;
	while (processed < inl - dataSize)
	{
		cipher.Encrypt(in + processed, dataSize, buffer, &bufferl);
		bufferAcc.append(buffer);
		bzero(buffer, sizeOfBuffer);
		processed += dataSize;
	}
	free(buffer);
	int encryptedl = bufferAcc.size();
	unsigned char *encrypted = (unsigned char *)OPENSSL_malloc(encryptedl);
	memmove(encrypted, bufferAcc.c_str(), encryptedl);
	cipher.FinishEncryption(encrypted, &encryptedl);

	// Encrypt the AES key with the Public key
	size_t cipherAesKeyl = 512;
	unsigned char *cipherAesKey = (unsigned char *)OPENSSL_malloc(cipherAesKeyl);
	if (!pkey_encrypt(pubkey, cipher.GetKey(), 32, cipherAesKey, &cipherAesKeyl))
	{
		log("Failed to encrypt file");
		free(encrypted);
		return (0);
	}

	stockholm::header *dat = (stockholm::header *)OPENSSL_malloc(sizeof(stockholm::header));
	memmove(dat->magic, "STOKOLM!", 8);
	memmove(dat->key, cipherAesKey, cipherAesKeyl);
	dat->content_size = encryptedl;
	sha256(in, inl, dat->file_hash);
	int fd = open(outfile, O_WRONLY | O_TRUNC | O_CREAT, 0644);
	if (fd < 0)
	{
		log("Failed to open outfile");
		free(encrypted);
		return (0);
	}
	printf("headerp %p\n", dat);
	write(fd, dat, sizeof(*dat));
	free(dat);
	write(fd, encrypted, encryptedl);
	close(fd);
	free(encrypted);
	return (1);
}

int rsa_aes_hybrid_decryption(const char *privkey,
							  const char *infile,
							  stockholm::header *header,
							  unsigned char **out,
							  int *outl)
{
	//! FIXME: https://gcc.gnu.org/onlinedocs/libstdc++/manual/fstreams.html#std.io.filestreams.binary
	std::ifstream file(infile, std::ios::in | std::ios::binary);
	if (!file.is_open())
	{
		log("Failed to open infile");
		return (0);
	}
	file.read((char *)header, sizeof(*header));
	unsigned char *cipherContent = new unsigned char[header->content_size];
	file.read((char *)cipherContent, header->content_size);
	file.close();

	unsigned char key[32];
	size_t keyl = 32;
	if (!pkey_decrypt(privkey, header->key, 512, key, &keyl))
	{
		log("Failed to decrypt file");
		delete[] cipherContent;
		return (0);
	}
	AES_256_CBC cipher = AES_256_CBC::NewCipherWithKey(key, AES_256_CBC::DecryptionMode);

	*outl = header->content_size;
	*out = new unsigned char[*outl];

	cipher.Decrypt(cipherContent, header->content_size, *out, outl);
	cipher.FinishDecryption(*out, outl);
	delete[] cipherContent;
	return (1);
}

int create_local_rsa_id(const char *master_public_pem)
{
	EVP_PKEY *pkey = new_rsa();
	if (!pkey)
	{
		log("Failed to create RSA PKEY");
		return (0);
	}
	void *p;
	size_t local_privkey_len = i2d_PrivateKey(pkey, NULL);
	unsigned char *local_privkey = (unsigned char *)OPENSSL_aligned_alloc(local_privkey_len, 16, &p);

	if (i2d_PrivateKey(pkey, &local_privkey) < 0)
	{
		LogOpenSSLError();
		EVP_PKEY_free(pkey);
		return (0);
	}
	if (!rsa_aes_hybrid_encryption(master_public_pem, "00000000.eky", local_privkey, local_privkey_len))
	{
		EVP_PKEY_free(pkey);
		return (0);
	}
	FILE *pubkey_fp = fopen("00000000.pky", "w");
	if (pubkey_fp)
		PEM_write_PUBKEY(pubkey_fp, pkey);
	else
		log(strerror(errno));
	EVP_PKEY_free(pkey);
	fclose(pubkey_fp);
	return (1);
}

// int main()
// {

// 	char data[] = "some data\nsome more data";
// 	rsa_aes_hybrid_encryption("00000000.pky", "out.file", (unsigned char *)data, sizeof(data) - 1);

// 	stockholm::header hdr;
// 	unsigned char *out;
// 	int outl;
// 	rsa_aes_hybrid_decryption("local_priv.pem", "out.file", &hdr, &out, &outl);
// 	printf("%s\n", out);
// 	delete[] out;
// 	return (0);
// }
