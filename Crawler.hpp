#pragma once

#include <string>
#include <list>
#include <filesystem>

namespace fs = std::filesystem;

std::list<std::string> RetrieveFilesInInfectionDirectory(void);
