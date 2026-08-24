#define OPENSSL_NO_DEPRECATED
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>

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
		ERR_print_errors_fp(stderr);
		return (NULL);
	}

	if (EVP_PKEY_keygen_init(ctx) < 1)
	{
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		return (NULL);
	}

	if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
	{
		ERR_print_errors_fp(stderr);
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
		ERR_print_errors_fp(stderr);
	if (EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_PADDING) < 1)
		ERR_print_errors_fp(stderr);
	if (EVP_PKEY_CTX_set_rsa_oaep_md(enc_ctx, EVP_sha256()) < 1)
		ERR_print_errors_fp(stderr);

	if (EVP_PKEY_encrypt(enc_ctx, out, outl, in, inl) < 1)
		ERR_print_errors_fp(stderr);
}

void pkey_decrypt(const char *path, unsigned char *in, size_t inl, unsigned char *out, size_t *outl)
{
	EVP_PKEY *priv_key = load_private_key(path);
	EVP_PKEY_CTX *dec_ctx = EVP_PKEY_CTX_new(priv_key, NULL);
	if (EVP_PKEY_decrypt_init(dec_ctx) < 1)
		ERR_print_errors_fp(stderr);
	if (EVP_PKEY_CTX_set_rsa_padding(dec_ctx, RSA_PKCS1_OAEP_PADDING) < 1)
		ERR_print_errors_fp(stderr);
	if (EVP_PKEY_CTX_set_rsa_oaep_md(dec_ctx, EVP_sha256()) < 1)
		ERR_print_errors_fp(stderr);

	if (EVP_PKEY_decrypt(dec_ctx, out, outl, in, inl) < 1)
		ERR_print_errors_fp(stderr);
}

int main()
{
	EVP_PKEY *pkey = new_rsa();

	unsigned char *local_privkey = new unsigned char[4096];
	size_t local_privkey_len = 4096;
	// EVP_PKEY_get_raw_private_key(pkey, local_privkey, &local_privkey_len);

	local_privkey_len = i2d_PrivateKey(pkey, &local_privkey);
	printf("%zu\n", local_privkey_len);

	unsigned char out[4096];
	size_t outl = 4096;
	pkey_encrypt("./public.pem", local_privkey, local_privkey_len, out, &outl);

	unsigned char decrypted_out[4096];
	size_t decrypted_outl = 4096;
	pkey_decrypt("./private.pem", out, outl, decrypted_out, &decrypted_outl);

	EVP_PKEY *local_private_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_RSA, NULL, decrypted_out, decrypted_outl);
	if (!local_private_pkey)
		ERR_print_errors_fp(stderr);

	PEM_write_PrivateKey(stdout, local_private_pkey, NULL, NULL, 0, NULL, NULL);

	EVP_PKEY_free(pkey);
	return (0);
}
