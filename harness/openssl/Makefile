CXXFLAGS = -std=c++17
CPPFLAGS = $(shell pkg-config --cflags libcrypto)
LDFLAGS = $(shell pkg-config --libs libcrypto)

.PHONY: all
all: main

.PHONY: debug
debug: CXXFLAGS += -fsanitize=address,undefined
debug: main

.PHONY: run
run: main
	./main

.PHONY: clean
clean:
	rm -f main
