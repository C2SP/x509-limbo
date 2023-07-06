ifdef $(BREW)
CXX = /opt/homebrew/opt/llvm/bin/clang++
endif

CXXFLAGS = -std=c++17
CPPFLAGS = `pkg-config --cflags openssl`
LDFLAGS = `pkg-config --libs openssl`

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
