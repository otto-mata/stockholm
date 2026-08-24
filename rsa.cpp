#define OPENSSL_NO_DEPRECATED
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <iostream>
#include <fstream>
#include "aes.hpp"
#include "log.hpp"
#include "stockholm.hpp"
#include "sha.hpp"

// https://www.techbuddies.io/2026/01/17/hands-on-openssl-c-crypto-examples-aes-rsa-hash-and-hmac/#Asymmetric_Encryption_in_C_with_OpenSSL_RSA_Key_Pair_and_Usage

EVP_PKEY *load_private_key(const char *path)
{
	FILE *fp = fopen(path, "r");
	if (!fp)
		return NULL;
	EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	return pkey; /* NULL on failure */
}

EVP_PKEY *load_public_key(const char *path)
{
	FILE *fp = fopen(path, "r");
	if (!fp)
		return NULL;
	EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
	fclose(fp);
	return pkey; /* NULL on failure */
}

EVP_PKEY *new_rsa(void)
{
	EVP_PKEY *pkey = NULL;

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (ctx == NULL)
	{
		log(ERR_reason_error_string(ERR_get_error()));

		return (NULL);
	}

	if (EVP_PKEY_keygen_init(ctx) < 1)
	{
		log(ERR_reason_error_string(ERR_get_error()));

		EVP_PKEY_CTX_free(ctx);
		return (NULL);
	}
	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 4096) <= 0)
	{
		log(ERR_reason_error_string(ERR_get_error()));

		EVP_PKEY_CTX_free(ctx);
		return (NULL);
	}

	if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
	{
		log(ERR_reason_error_string(ERR_get_error()));
		EVP_PKEY_free(pkey);
		return (NULL);
	}
	EVP_PKEY_CTX_free(ctx);
	return pkey;
}

void pkey_encrypt(const char *path, unsigned char *in, size_t inl, unsigned char *out, size_t *outl)
{
	// PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);
	// PEM_write_PUBKEY(stdout, pkey);

	EVP_PKEY *pub_key = load_public_key(path);
	EVP_PKEY_CTX *enc_ctx = EVP_PKEY_CTX_new(pub_key, NULL);
	if (EVP_PKEY_encrypt_init(enc_ctx) < 1)
		log(ERR_reason_error_string(ERR_get_error()));

	if (EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_OAEP_PADDING) < 1)
		log(ERR_reason_error_string(ERR_get_error()));

	if (EVP_PKEY_CTX_set_rsa_oaep_md(enc_ctx, EVP_sha256()) < 1)
		log(ERR_reason_error_string(ERR_get_error()));

	size_t tmp_len = 0;
	if (EVP_PKEY_encrypt(enc_ctx, NULL, &tmp_len, in, inl) < 1)
		log(ERR_reason_error_string(ERR_get_error()));

	if (*outl < tmp_len)
		*outl = tmp_len;
	if (EVP_PKEY_encrypt(enc_ctx, out, &tmp_len, in, inl) < 1)
		log(ERR_reason_error_string(ERR_get_error()));
	*outl = tmp_len;
	EVP_PKEY_CTX_free(enc_ctx);
}

void pkey_decrypt(const char *path, unsigned char *in, size_t inl, unsigned char *out, size_t *outl)
{
	EVP_PKEY *priv_key = load_private_key(path);
	EVP_PKEY_CTX *dec_ctx = EVP_PKEY_CTX_new(priv_key, NULL);
	if (EVP_PKEY_decrypt_init(dec_ctx) < 1)
		log(ERR_reason_error_string(ERR_get_error()));
	if (EVP_PKEY_CTX_set_rsa_padding(dec_ctx, RSA_PKCS1_OAEP_PADDING) < 1)
		log(ERR_reason_error_string(ERR_get_error()));
	if (EVP_PKEY_CTX_set_rsa_oaep_md(dec_ctx, EVP_sha256()) < 1)
		log(ERR_reason_error_string(ERR_get_error()));
	size_t tmp_len = 0;
	if (EVP_PKEY_decrypt(dec_ctx, NULL, &tmp_len, in, inl) < 1)
		log(ERR_reason_error_string(ERR_get_error()));

	if (*outl < tmp_len)
		*outl = tmp_len;
	if (EVP_PKEY_decrypt(dec_ctx, out, &tmp_len, in, inl) < 1)
		log(ERR_reason_error_string(ERR_get_error()));

	*outl = tmp_len;
	EVP_PKEY_CTX_free(dec_ctx);
}

void rsa_aes_hybrid_encryption(const char *pubkey, const char *outfile, unsigned char *in, size_t inl)
{

	// Encrypt with AES 256 CBC, random key
	int encryptedl = AES_256_CBC::SizeOfCipher(inl);
	unsigned char *encrypted = new unsigned char[encryptedl];
	AES_256_CBC cipher = AES_256_CBC::NewCipherWithRandomKey(AES_256_CBC::EncryptionMode);
	cipher.Encrypt(in, inl, encrypted, &encryptedl);
	cipher.FinishEncryption(encrypted, &encryptedl);

	// Encrypt the AES key with the Public key
	unsigned char cipherAesKey[512];
	size_t cipherAesKeyl = 512;
	pkey_encrypt(pubkey, cipher.GetKey(), 32, cipherAesKey, &cipherAesKeyl);

	stockholm::header dat = stockholm::header();
	memmove(dat.key, cipherAesKey, cipherAesKeyl);
	dat.content_size = encryptedl;
	sha256(in, inl, dat.file_hash);

	std::ofstream file(outfile, std::ios::out | std::ios::binary | std::ios::trunc);
	if (!file.is_open())
	{
		log("Failed to open outfile");
		delete[] encrypted;
		return;
	}
	file.write((char *)&dat, sizeof(dat));
	file.write((char *)encrypted, encryptedl);
	file.close();

	delete[] encrypted;
}

void rsa_aes_hybrid_decryption(const char *privkey,
							   const char *infile,
							   stockholm::header *header,
							   unsigned char **out,
							   int *outl)
{
	std::ifstream file(infile, std::ios::in | std::ios::binary);
	if (!file.is_open())
	{
		log("Failed to open infile");
		return;
	}
	file.read((char *)header, sizeof(*header));
	unsigned char *cipherContent = new unsigned char[header->content_size];
	file.read((char *)cipherContent, header->content_size);
	file.close();

	unsigned char key[32];
	size_t keyl = 32;
	pkey_decrypt(privkey, header->key, 512, key, &keyl);
	AES_256_CBC cipher = AES_256_CBC::NewCipherWithKey(key, AES_256_CBC::DecryptionMode);

	*outl = header->content_size;
	*out = new unsigned char[*outl];

	cipher.Decrypt(cipherContent, header->content_size, *out, outl);
	cipher.FinishDecryption(*out, outl);
	delete[] cipherContent;
}

void create_local_rsa_id(const char *master_public_pem)
{
	EVP_PKEY *pkey = new_rsa();
	// Retrieve private key

	size_t local_privkey_len = i2d_PrivateKey(pkey, NULL);
	unsigned char *local_privkey = new unsigned char[local_privkey_len];
	i2d_PrivateKey(pkey, &local_privkey);

	rsa_aes_hybrid_encryption(master_public_pem, "00000000.eky", local_privkey, local_privkey_len);

	FILE *pubkey_fp = fopen("00000000.pky", "w");
	if (pubkey_fp)
		PEM_write_PUBKEY(pubkey_fp, pkey);
	else
		log(strerror(errno));
	EVP_PKEY_free(pkey);
}

int main()
{

	char data[] = "some data\nsome more data";
	rsa_aes_hybrid_encryption("00000000.pky", "out.file", (unsigned char *)data, sizeof(data) - 1);

	stockholm::header hdr;
	unsigned char *out;
	int outl;
	rsa_aes_hybrid_decryption("local_priv.pem", "out.file", &hdr, &out, &outl);
	printf("%s\n", out);
	delete[] out;
	return (0);
}
