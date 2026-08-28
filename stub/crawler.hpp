#pragma once

#include <string>
#include <list>
#include <filesystem>
#include "stockholm.hpp"

std::list<std::string> RetrieveFilesFrom(fs::path from);
