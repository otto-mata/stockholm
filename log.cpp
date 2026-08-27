#include <iostream>
#include <source_location>
#include <string_view>

void log(const std::string_view message,
		 const std::source_location location =
			 std::source_location::current())
{
	std::clog << "[LOG] "
			  << location.file_name() << '('
			  << location.line() << ':'
			  << location.column() << ") `"
			  << location.function_name() << "`: "
			  << message << '\n';
}

void print_hex(unsigned char *data, size_t datal)
{
	for (size_t i = 0; i < datal; i++)
		printf("%x", data[i]);
	printf("\n");
}
