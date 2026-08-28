#pragma once
#include <filesystem>

namespace fs = std::filesystem;

class opts
{
private:
	bool reverse;
	fs::path keyfilePath;
	fs::path infectionDir;
	bool silent;
	bool version;

public:
	opts();
	opts(int argc, char **argv);
	opts(const opts &rhs);
	opts &operator=(const opts &rhs);

	void SetDefault();
	bool ShouldDisplayVersion();
	bool IsInSilentMode();
	bool IsInDecryptionMode();
	fs::path &GetKeyfilePath() const;
	void SetInfectionDir(const fs::path &path);
	fs::path &GetInfectionDir() const;
};
