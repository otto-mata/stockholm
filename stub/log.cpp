#include "stockholm.hpp"
#include <iostream>
#include <source_location>
#include <string_view>
#include <openssl/err.h>
#include <cstring>
#include <sstream>
#include <chrono>

namespace
{
	std::string _getTime()
	{
		return std::format("{0:%FT%OH:%OM:%OS%Ez}", std::chrono::system_clock::now());
	}

	void _log(const std::string_view tag, const std::string_view message)
	{
		if (!stockholm::options.IsInSilentMode())
			std::clog << std::format("[{0}][{1}] ", _getTime(), tag)
					  << message << '\n';
	}

	void _detailed_log(
		const std::string_view tag, const std::string_view message,
		const std::source_location location)
	{

		std::ostringstream ss;

		ss << location.file_name() << ':'
		   << location.line() << ':'
		   << location.column() << ": "
		   << message;
		_log(tag, ss.str());
	}
} // namespace

void Log(const std::string_view message)
{
	_log("INFO", message);
}

void Error(const std::string_view message,
		   const std::source_location location =
			   std::source_location::current())
{
	_detailed_log("ERROR", message, location);
}

void Perror(const std::string_view source,
			const std::source_location location =
				std::source_location::current())
{
	std::ostringstream ss;
	ss << source << ": " << strerror(errno);
	Error(ss.str(), location);
}

void LogOpenSSLError(const std::source_location location =
						 std::source_location::current())
{
	const char *error = ERR_reason_error_string(ERR_get_error());
	if (!error)
		error = strerror(errno);
	Error(error, location);
}
