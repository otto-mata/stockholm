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
		EVP_PKEY_free(pub_key);
		return (0);
	}

	if (EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_OAEP_PADDING) < 1)
	{
		LogOpenSSLError();
		EVP_PKEY_CTX_free(enc_ctx);
		EVP_PKEY_free(pub_key);
		return (0);
	}

	if (EVP_PKEY_CTX_set_rsa_oaep_md(enc_ctx, EVP_sha256()) < 1)
	{
		LogOpenSSLError();
		EVP_PKEY_CTX_free(enc_ctx);
		EVP_PKEY_free(pub_key);
		return (0);
	}

	size_t tmp_len = 0;
	if (EVP_PKEY_encrypt(enc_ctx, NULL, &tmp_len, in, inl) < 1)
	{
		LogOpenSSLError();
		EVP_PKEY_CTX_free(enc_ctx);
		EVP_PKEY_free(pub_key);
		return (0);
	}

	if (*outl < tmp_len)
		*outl = tmp_len;

	if (EVP_PKEY_encrypt(enc_ctx, out, &tmp_len, in, inl) < 1)
	{
		LogOpenSSLError();
		EVP_PKEY_CTX_free(enc_ctx);
		EVP_PKEY_free(pub_key);
		return (0);
	}

	*outl = tmp_len;
	EVP_PKEY_CTX_free(enc_ctx);
	EVP_PKEY_free(pub_key);
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
		EVP_PKEY_free(priv_key);
		return (0);
	}
	if (EVP_PKEY_CTX_set_rsa_padding(dec_ctx, RSA_PKCS1_OAEP_PADDING) < 1)
	{
		LogOpenSSLError();
		EVP_PKEY_CTX_free(dec_ctx);
		EVP_PKEY_free(priv_key);
		return (0);
	}
	if (EVP_PKEY_CTX_set_rsa_oaep_md(dec_ctx, EVP_sha256()) < 1)
	{
		LogOpenSSLError();
		EVP_PKEY_CTX_free(dec_ctx);
		EVP_PKEY_free(priv_key);
		return (0);
	}
	size_t tmp_len = 0;
	if (EVP_PKEY_decrypt(dec_ctx, NULL, &tmp_len, in, inl) < 1)
	{
		LogOpenSSLError();
		EVP_PKEY_CTX_free(dec_ctx);
		EVP_PKEY_free(priv_key);
		return (0);
	}

	if (*outl < tmp_len)
		*outl = tmp_len;
	if (EVP_PKEY_decrypt(dec_ctx, out, &tmp_len, in, inl) < 1)
	{
		LogOpenSSLError();
		EVP_PKEY_CTX_free(dec_ctx);
		EVP_PKEY_free(priv_key);
		return (0);
	}

	*outl = tmp_len;
	EVP_PKEY_CTX_free(dec_ctx);
	EVP_PKEY_free(priv_key);
	return (1);
}

int rsa_aes_hybrid_encryption(const char *pubkey, BIO *in, BIO *out)
{
	size_t input_length = BIO_ctrl_pending(in);
	unsigned char *input = new unsigned char[input_length];
	BIO_read(in, input, input_length);

	AES_256_CBC cipher = AES_256_CBC::NewCipherWithRandomKey(AES_256_CBC::EncryptionMode);
	printf("Key for encryption: ");
	print_hex(cipher.GetKey(), 32);

	// Allocate buffer big enough for ciphertext + padding (up to 1 block extra)
	int max_encrypted_len = input_length + EVP_CIPHER_get_block_size(EVP_aes_256_cbc());
	unsigned char *encrypted = new unsigned char[max_encrypted_len];

	int update_len = 0;
	int final_len = 0;

	// 1. Encrypt all input data in a single call
	cipher.Encrypt(input, input_length, encrypted, &update_len);

	// 2. Append final padded block at the correct offset
	cipher.FinishEncryption(encrypted + update_len, &final_len);

	int total_encrypted_len = update_len + final_len;
	printf("Total enc-data: %d bytes\n", total_encrypted_len);

	// 3. Encrypt the AES key with RSA Public key
	size_t cipherAesKeyl = 512;
	unsigned char *cipherAesKey = new unsigned char[cipherAesKeyl];
	if (!pkey_encrypt(pubkey, cipher.GetKey(), 32, cipherAesKey, &cipherAesKeyl))
	{
		log("Failed to encrypt file");
		delete[] input;
		delete[] encrypted;
		delete[] cipherAesKey;
		return (0);
	}

	// 4. Build and write header
	stockholm::header *dat = (stockholm::header *)OPENSSL_malloc(sizeof(stockholm::header));
	memset(dat, 0, sizeof(*dat));
	memmove(dat->magic, "STOKOLM!", 8);
	memmove(dat->key, cipherAesKey, cipherAesKeyl);
	delete[] cipherAesKey;

	dat->cipher_size = total_encrypted_len;
	dat->raw_size = input_length;
	sha256(input, input_length, dat->file_hash);
	delete[] input;

	// 5. Write Header and Encrypted Stream
	BIO_write(out, dat, sizeof(*dat));
	free(dat);
	BIO_write(out, encrypted, total_encrypted_len);
	delete[] encrypted;

	return (1);
}

int rsa_aes_hybrid_decryption(const char *privkey,
							  stockholm::header *header,
							  BIO *in,
							  BIO *out)
{

	BIO_read(in, header, sizeof(*header));
	unsigned char *input = new unsigned char[header->cipher_size];
	BIO_read(in, input, header->cipher_size);

	unsigned char key[32];
	size_t keyl = 32;
	if (!pkey_decrypt(privkey, header->key, 512, key, &keyl))
	{
		log("Failed to decrypt file");
		delete[] input;
		return (0);
	}
	AES_256_CBC cipher = AES_256_CBC::NewCipherWithKey(key, AES_256_CBC::DecryptionMode);

	printf("Key for decryption: ");
	print_hex(cipher.GetKey(), 32);

	unsigned char *out_buffer = new unsigned char[header->cipher_size + 16];
	int update_len = 0;
	int final_len = 0;

	// 1. Decrypt update
	cipher.Decrypt(input, header->cipher_size, out_buffer, &update_len);
	cipher.FinishDecryption(out_buffer + update_len, &final_len);
	delete[] input;
	int total_len = update_len + final_len;
	size_t actual;
	BIO_write_ex(out, out_buffer, total_len, &actual);
	delete[] out_buffer;
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
	BIO *mem = BIO_new(BIO_s_mem());
	if (!mem)
	{
		LogOpenSSLError();
		EVP_PKEY_free(pkey);
		return (0);
	}
	if (!PEM_write_bio_PrivateKey(mem, pkey, NULL, NULL, 0, NULL, NULL))
	{
		LogOpenSSLError();
		EVP_PKEY_free(pkey);
		return (0);
	}
	BIO *out_mem = BIO_new(BIO_s_mem());
	if (!out_mem)
	{
		LogOpenSSLError();
		EVP_PKEY_free(pkey);
		return (0);
	}
	if (!rsa_aes_hybrid_encryption(master_public_pem, mem, out_mem))
	{
		EVP_PKEY_free(pkey);
		return (0);
	}
	BIO_free(mem);
	FILE *pubkey_fp = fopen("00000000.pky", "wb");
	if (pubkey_fp)
		PEM_write_PUBKEY(pubkey_fp, pkey);
	else
		log(strerror(errno));
	fclose(pubkey_fp);
	FILE *privkey_fp = fopen("00000000.eky", "wb");
	if (!privkey_fp)
		log(strerror(errno));
	else
	{
		char buffer[1024];
		size_t len;
		do
		{
			BIO_read_ex(out_mem, buffer, 1024, &len);
			fwrite(buffer, sizeof(char), len, privkey_fp);
		} while (len);
		fclose(privkey_fp);
	}
	EVP_PKEY_free(pkey);
	BIO_free(out_mem);
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
