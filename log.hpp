#pragma once
#include <source_location>
#include <string_view>

void log(const std::string_view message,
		 const std::source_location location =
			 std::source_location::current());
