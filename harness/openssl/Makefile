CXXFLAGS = -std=c++17

ifeq ($(BORINGSSL),)
CPPFLAGS = $(shell pkg-config --cflags libcrypto)
LDLIBS = $(shell pkg-config --libs libcrypto)
else
# NOTE: too lazy to do this generically; this assumes the boringssl container.
CPPFLAGS = -I/build/boringssl/include
LDLIBS = -L/build/boringssl/lib -lcrypto
endif

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

boringssl: boringssl.dockerfile
	docker build --platform linux/amd64 -f $< . -t x509-limbo-$@
