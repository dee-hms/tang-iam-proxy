#!/bin/bash
#
# Copyright 2023 sarroutb@redhat.com
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom
# the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
# OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
certname="server"
passphrase_file="passphrase.txt"
test -n "$1" && certname="$1"

printf "*************************\n"
printf "certname:%s\n" "${certname}"
printf "*************************\n"

# Generate a passphrase
openssl rand -base64 48 > "${passphrase_file}"
#
# # Generate a Private Key
openssl genrsa -aes128 -passout file:"${passphrase_file}" -out "${certname}.key" 2048
#
# # Generate a CSR (Certificate Signing Request)
openssl req -new -passin file:"${passphrase_file}" -key "${certname}.key" -out "${certname}.csr" \
        -subj "/C=ES/ST=Madrid/L=Madrid/O=Red Hat/OU=org/CN=www.redhat.com"
#
# Remove Passphrase from Key
cp "${certname}.key" "${certname}.key.org"
openssl rsa -in "${certname}.key.org" -passin file:"${passphrase_file}" -out "${certname}.key"

# Generating a Self-Signed Certificate for 100 years
openssl x509 -req -days 36500 -in "${certname}.csr" -signkey "${certname}.key" -out "${certname}.crt"

