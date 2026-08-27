#pragma once
#include <source_location>
#include <string_view>
#define LogOpenSSLError() log(ERR_reason_error_string(ERR_get_error()))

void log(const std::string_view message,
		 const std::source_location location =
			 std::source_location::current());

void print_hex(unsigned char *data, size_t datal);
