#!/bin/sh
set -e
# This scripts modifies an existing cryptography.io chain so that its root
# certificate has mismatching `signatureAlgorithm` fields

# Get all the certificates in the cryptography.io chain in separate certNN files
split -d -p "----BEGIN CERTIFICATE-----" ../cryptography.io.pem cert

# Store the root certificate in DER format
openssl x509 -in cert00 -outform DER -out cryptography.io_root.der

# The certificate contains two occurrences of signatureAlgorithm: the first one
# is inside of the TBS section, and the second one is outside of it. In order to
# create a certificate with mismatching signatureAlgorithms, we modify only the
# second occurrence (outside the TBS section), because it's not signed.

# The OID for RSAWithSHA256 is 1.2.840.113549.1.1.11 (hex: 06092a864886f70d01010b)
# The OID for RSAWithSHA512 is 1.2.840.113549.1.1.13 (hex: 06092a864886f70d01010d)

xxd -p cryptography.io_root.der | tr -d '\n' |
 sed 's/06092a864886f70d01010b/06092a864886f70d01010d/2' |
 xxd -p -r > root_mismatched.der

# Encode back to PEM
openssl x509 -inform der -in root_mismatched.der -out root_mismatched.pem

# Create a new chain replacing the original root with the mismatched algorithms root
cat root_mismatched.pem cert01 cert02 > ../cryptography.io_mismatched.pem

rm cryptography.io_root.der root_mismatched.der root_mismatched.pem cert0*
