#!/usr/bin/env bash

set -e

# OpenSSL calls secp256r1 "prime256v1"
openssl ecparam \
    -name prime256v1 \
    -genkey \
    -param_enc explicit \
    -noout \
    -outform PEM \
    -out ../explicit_curve_ca.key

openssl ecparam \
    -name prime256v1 \
    -genkey \
    -param_enc explicit \
    -noout \
    -outform PEM \
    -out ../explicit_curve_leaf.key
