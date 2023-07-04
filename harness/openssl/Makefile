CXXFLAGS = -std=c++11 -fsanitize=address
CPPFLAGS = -I /opt/homebrew/opt/openssl@3/include
LDFLAGS = -L /opt/homebrew/opt/openssl@3/lib
LDLIBS = -l crypto

.PHONY: all
all: main

.PHONY: clean
clean:
	rm -f main
