#pragma once

#include <string>
#include <list>
#include <filesystem>

namespace fs = std::filesystem;

std::list<std::string> RetrieveFilesFrom(fs::path from);
