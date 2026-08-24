#pragma once
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

//! TODO: Add mode selection encrypt/decrypt
//! TODO: Add better error handling
class AES_256_CBC
{
public:
	enum MODE
	{
		EncryptionMode,
		DecryptionMode
	};
	AES_256_CBC(unsigned char *_key, unsigned char *_iv, MODE _mode);
	~AES_256_CBC();

	void Init();
	void Decrypt(unsigned char *in, int inl, unsigned char *out, int *outl);
	void FinishDecryption(unsigned char *out, int *outl);
	void Encrypt(unsigned char *in, int inl, unsigned char *out, int *outl);
	void FinishEncryption(unsigned char *out, int *outl);
	unsigned char *GetKey(void);

	static AES_256_CBC NewCipherWithRandomKey(MODE _mode);
	static AES_256_CBC NewCipherWithKey(unsigned char *key, MODE _mode);
	static size_t SizeOfCipher(size_t clear_size);

private:
	unsigned char key[32];
	unsigned char iv[16];
	bool error;
	bool init;
	EVP_CIPHER_CTX *ctx;
	const EVP_CIPHER *cipher;
	AES_256_CBC::MODE mode;

	void initEncryption();
	void initDecryption();
};
