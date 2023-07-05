#!/bin/bash
#
# Copyright 2023
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
certname="server"
test -n "$1" && certname="$1"

printf "*************************\n"
printf "certname:%s\n" "${certname}"
printf "*************************\n"


############################# Generate CA ###############################
openssl genrsa -out ca_${certname}.key 4096
openssl req -new -x509 -days 365 -key ca_${certname}.key -out ca_${certname}_cert.pem -subj "/C=ES/ST=Madrid/L=Madrid/O=Red Hat/OU=org/CN=www.redhat.com"
#########################################################################


############################# Generate Server certificate ################################
cat<<EOF>${certname}_cert_ext.cnf
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names
[alt_names]
IP.1 = 1.2.3.4
DNS.1 = fedora
DNS.2 = localhost
EOF

openssl genrsa -out ${certname}.key 4096
openssl req -new -key ${certname}.key -out ${certname}.csr -subj "/C=ES/ST=Madrid/L=Madrid/O=Red Hat/OU=org/CN=www.redhat.com"
openssl x509 -req -in ${certname}.csr -CA ca_${certname}_cert.pem -CAkey ca_${certname}.key -out ${certname}.crt -CAcreateserial -days 365 -sha256 -extfile ${certname}_cert_ext.cnf
########################################################################################


############################# Create Server bundle #####################################
cat ${certname}.crt > ${certname}_bundle.pem
cat ca_${certname}_cert.pem >> ${certname}_bundle.pem
########################################################################################
