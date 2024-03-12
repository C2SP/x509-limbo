#!/usr/bin/env bash

set -e

ca_csr_conf='
[ req ]
default_md = sha256
prompt = no
req_extensions = req_ext
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
commonName = x509-limbo-explicit-ec-root
[ req_ext ]
keyUsage=critical,keyCertSign,cRLSign
basicConstraints=critical,CA:true
'

leaf_csr_conf='
[ req ]
default_md = sha256
prompt = no
req_extensions = req_ext
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
commonName = example.com
[ req_ext ]
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
basicConstraints=critical,CA:false
subjectAltName = @alt_names
[ alt_names ]
DNS.0 = example.com
'

# CA CSR
openssl req \
    -new \
    -noenc \
    -key ../explicit_curve_ca.key \
    -config <(echo "${ca_csr_conf}") \
    -nameopt utf8 \
    -utf8 \
    -out ../explicit_curve_ca.csr

# Self-signed CA (with explicit EC encoding)
openssl x509 \
    -signkey ../explicit_curve_ca.key \
    -days 365 \
    -req -in ../explicit_curve_ca.csr \
    -out ../explicit_curve_ca.pem

# Leaf CSR
openssl req \
    -new \
    -noenc \
    -key ../explicit_curve_leaf.key \
    -config <(echo "${leaf_csr_conf}") \
    -nameopt utf8 \
    -utf8 \
    -out ../explicit_curve_leaf.csr

# Leaf certificate (with explicit EC encoding)
openssl x509 \
    -days 365 \
    -req -in ../explicit_curve_leaf.csr \
    -CA ../explicit_curve_ca.pem \
    -CAkey ../explicit_curve_ca.key \
    -out ../explicit_curve_leaf.pem
