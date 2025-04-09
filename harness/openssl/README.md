# OpenSSL test harness for x509-limbo

This directory contains a basic test harness for running the x509-testsuite
against OpenSSL.

OpenSSL 1.1, 3.0, and forwards should all work.

## Building

On Linux with OpenSSL installed, building should be as simple as:

```bash
# build normally
make

# build with sanitizers, etc.
make debug
```

On macOS, you'll need to tell the build where to find the version of OpenSSL
to use. The easiest way to do that is to use `brew` and `PKG_CONFIG_PATH`, e.g.:

```bash
# install the version of OpenSSL you'd like to test
brew install openssl@3.1

PKG_CONFIG_PATH="$(brew --prefix)/opt/openssl@3.1/lib/pkgconfig" make
```
