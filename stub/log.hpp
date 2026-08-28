#pragma once
#include <source_location>
#include <string_view>

void Error(const std::string_view message,
		   const std::source_location location =
			   std::source_location::current());

void Perror(const std::string_view source,
			const std::source_location location =
				std::source_location::current());

void Log(const std::string_view message);

void LogOpenSSLError(
	const std::source_location location =
		std::source_location::current());
