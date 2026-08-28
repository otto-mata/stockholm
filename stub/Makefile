TARGET := stockholm
CXX := g++
CXXFLAGS := -std=gnu++23 -Wall -Wextra -Werror
LDFLAGS := -lcrypto
SOURCE := aes.cpp crawler.cpp log.cpp main.cpp opts.cpp rsa.cpp sha.cpp stockholm.cpp
OBJS := $(SOURCE:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f $(OBJS)

fclean: clean
	rm -f $(TARGET)

re: fclean all

.PHONY: all clean fclean re
