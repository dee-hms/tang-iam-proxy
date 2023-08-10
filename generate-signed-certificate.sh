#!/bin/bash -e
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
sub_alt_name="tang-backend-tang"

function usage() {
  echo
  echo "$1 [-n name] [-s subAlternateName][-h] [-v]"
  echo
  echo "Examples:"
  echo "        $1 -n server -s tang-iam-proxy-passthrough"
  echo
  echo "Options:"
  echo "        -n \"name\": Base name for generated files"
  echo "        -s \"subAlternateName\": extra Subject Alternate Name for server certificate"
  echo "        -h: help"
  echo
  exit "$2"
}

while getopts "n:s:h" arg
do
  case "${arg}" in
    n) certname=${OPTARG}
       ;;

    s) sub_alt_name=${OPTARG}
       ;;
    h) usage "$0" 0
       ;;
    *) usage "$0" 1
       ;;
  esac
done

printf "*****************************************\n"
printf "certname:%s\n" "${certname}"
printf "sub_alternate_name:%s\n" "${sub_alt_name}"
printf "*****************************************\n"

############################# Generate CA ###############################
openssl genrsa -out "ca_${certname}.key" 4096
openssl req -new -x509 -days 365 -key "ca_${certname}.key" -out "ca_${certname}_cert.pem" -subj "/C=ES/ST=Madrid/L=Madrid/O=Red Hat/OU=org/CN=www.redhat.com"
#########################################################################


############################# Generate Server certificate ################################
cat<<EOF>"${certname}_cert_ext.cnf"
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
DNS.3 = ${sub_alt_name}
EOF

openssl genrsa -out "${certname}.key" 4096
openssl req -new -key "${certname}.key" -out "${certname}.csr" -subj "/C=ES/ST=Madrid/L=Madrid/O=Red Hat/OU=org/CN=www.redhat.com"
openssl x509 -req -in "${certname}.csr" -CA "ca_${certname}_cert.pem" -CAkey "ca_${certname}.key" -out "${certname}.crt" -CAcreateserial -days 365 -sha256 -extfile "${certname}_cert_ext.cnf"
chmod 664 "${certname}.key"
########################################################################################


############################# Create Server bundle #####################################
cat "${certname}.crt" > "${certname}_bundle.pem"
cat "ca_${certname}_cert.pem" >> "${certname}_bundle.pem"
########################################################################################


############################# Clean intermediate files #####################################
rm "${certname}.crt"
rm "${certname}.csr"
rm "ca_${certname}_cert.srl"
rm "ca_${certname}.key"
rm "${certname}_cert_ext.cnf"
#############################################################################################
