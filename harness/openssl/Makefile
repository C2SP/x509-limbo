CXXFLAGS = -std=c++17
CPPFLAGS = $(shell pkg-config --cflags libcrypto)
LDLIBS = $(shell pkg-config --libs libcrypto)

.PHONY: all
all: main

.PHONY: debug
debug: CXXFLAGS += -g -fsanitize=address,undefined
debug: main

.PHONY: clean
clean:
	rm -f main

openssl-%: openssl-%.dockerfile
	docker build --platform linux/amd64 -f $< . -t x509-limbo-$@
