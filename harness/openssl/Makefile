CXX = /opt/homebrew/opt/llvm/bin/clang++
CXXFLAGS = -std=c++17
CPPFLAGS = -I /opt/homebrew/opt/openssl@3.1/include
LDFLAGS = -L /opt/homebrew/opt/openssl@3.1/lib
LDLIBS = -l crypto

.PHONY: all
all: main

.PHONY: debug
debug: CXXFLAGS += -fsanitize=address,leak,undefined
debug: main

.PHONY: run
run: main
	./main

.PHONY: clean
clean:
	rm -f main
