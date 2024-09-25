CXXFLAGS = -std=c++17

# NOTE: too lazy to do this generically; this assumes the boringssl container.
CPPFLAGS = -I/build/boringssl/include
LDLIBS = /build/boringssl/lib/libcrypto.a /build/boringssl/lib/libpki.a

.PHONY: all
all: main

.PHONY: debug
debug: CXXFLAGS += -g -fsanitize=address,undefined
debug: main

.PHONY: clean
clean:
	rm -f main

boringssl: boringssl.dockerfile
	docker build --platform linux/amd64 -f $< . -t x509-limbo-$@
