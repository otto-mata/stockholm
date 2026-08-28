#include "opts.hpp"
#include "stockholm.hpp"
#include <getopt.h>
#include <cstring>
#include <iostream>

namespace
{
	void print_usage()
	{
		std::cout << "Usage: stockholm [-r[everse] <keyfile_path>] ";
		std::cout << "[-s[ilent]] [-v[ersion]] [-h[elp]]" << std::endl;
		std::cout << "\t-h, -[-]help\t\tDisplay this help and exit" << std::endl;
		std::cout << "\t-v, -[-]version\t\tDisplay the version and exit" << std::endl;
		std::cout << "\t-s, -[-]silent\t\tDon't log file actions" << std::endl;
		std::cout << "\t-r, -[-]reverse <path>\tDecrypt files using the supplied private key." << std::endl;
	}
}

opts::opts()
{
	reverse = false;
	silent = false;
	keyfilePath = fs::path();
	version = false;
}

opts::opts(int argc, char **argv)
{
	int optindex;
	int c;
	bool help = false;
	bool error = false;

	reverse = false;
	silent = false;
	keyfilePath = fs::path();
	version = false;

	opterr = 0;

	while (1)
	{
		optindex = optind ? optind : 1;
		struct option longOptions[] = {
			{"reverse", required_argument, 0, 0},
			{"version", no_argument, 0, 0},
			{"silent", no_argument, 0, 0},
			{"help", no_argument, 0, 0},
			{0, 0, 0, 0},
		};
		c = getopt_long_only(argc, argv, "r:vsh", longOptions, &optindex);
		if (c < 0)
			break;
		switch (c)
		{
		case 0:
			switch (optindex)
			{
			case 0:
				reverse = true;
				keyfilePath = optarg;
				break;
			case 1:
				version = true;
				break;
			case 2:
				silent = true;
				break;
			case 3:
				help = true;
				break;
			default:
				break;
			}
			break;
		case 'r':
			reverse = true;
			keyfilePath = optarg;
			break;
		case 'v':
			version = true;
			break;
		case 's':
			silent = true;
			break;
		case 'h':
			help = true;
			break;
		case '?':
			error = 1;
			break;
		default:
			break;
		}
		if (error)
			break;
	}
	if (help || error)
	{
		print_usage();
		exit(0);
	}
}

opts::opts(const opts &rhs)
{
	reverse = rhs.reverse;
	keyfilePath.assign(rhs.keyfilePath);
	silent = rhs.silent;
	version = rhs.version;
}

opts &opts::operator=(const opts &rhs)
{
	if (&rhs == this)
		return (*this);
	reverse = rhs.reverse;
	keyfilePath.assign(rhs.keyfilePath);
	silent = rhs.silent;
	version = rhs.version;
	return (*this);
}

void opts::SetDefault()
{
	reverse = false;
	silent = false;
	version = false;
}

bool opts::ShouldDisplayVersion()
{
	return version;
}

bool opts::IsInSilentMode()
{
	return silent;
}

bool opts::IsInDecryptionMode()
{
	return reverse;
}

fs::path &opts::GetKeyfilePath() const
{
	return const_cast<fs::path &>(keyfilePath);
}

void opts::SetInfectionDir(const fs::path &path)
{
	infectionDir = path;
}

fs::path &opts::GetInfectionDir() const
{
	return const_cast<fs::path &>(infectionDir);
}
