# http-server-x509-svid-parser

## License

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Status

[![Golang CI lint](https://github.com/dee-hms/http-server-x509-svid-parser/actions/workflows/golangci-lint.yaml/badge.svg)](https://github.com/dee-hms/http-server-x509-svid-parser/actions/workflows/golangci-lint.yaml)\
[![Staticcheck](https://github.com/dee-hms/http-server-x509-svid-parser/actions/workflows/staticcheck.yaml/badge.svg)](https://github.com/dee-hms/http-server-x509-svid-parser/actions/workflows/staticcheck.yaml)\
[![Shellcheck](https://github.com/dee-hms/http-server-x509-svid-parser/actions/workflows/shellcheck.yaml/badge.svg)](https://github.com/dee-hms/http-server-x509-svid-parser/actions/workflows/shellcheck.yaml)\
[![Spellcheck](https://github.com/dee-hms/http-server-x509-svid-parser/actions/workflows/spellcheck.yaml/badge.svg)](https://github.com/dee-hms/http-server-x509-svid-parser/actions/workflows/spellcheck.yaml)

## Introduction
This server is an HTTPS server that parses X509 client certificate and extracts SVID from Subject Alternate Names extension.
Main purpose of the server is to show how to extract previous information from the SPIRE agent generated certificates.
In this document it is explained how to generate required scripts for server and how to run `curl` application to act
as a client that sends the agent certificate.
The HTTPS server will parse client certificate, and dump the corresponding parsed information. It will also check in database
if receiving SPIRE ID is registered and, if so, it will forward the request.

## Certificate generation
The script `generate-signed-certificate.sh` has been included to generate the corresponding certificates.
It can be provided a parameter to name the certificates. Otherwise, the naming used will be *server*.

To generate the scripts, execute it:

```bash
$ ./generate-signed-certificate.sh
*************************
certname:server
*************************
Certificate request self-signature ok
subject=C = ES, ST = Madrid, L = Madrid, O = Red Hat, OU = org, CN = www.redhat.com
```

The script will generate a collection of certificates. The ones that will be used are:

* `ca_server_cert.pem`: This file will be used as the CA certificate
* `server_bundle.pem`: File that will act as the server certificate
* `server.key`: File that will be used as the server private key


## Server execution
The server has next usage:

```bash
$ ./http-server-x509-svid-parser -help

usage:

http_server_x509_svid_parser -serverCert <serverCertificateFile> -serverKey <serverPrivateKeyFile> -tangServer <tangServer>
                            [-port <port>] [-dbUser <dbuser>] [-dbPass <dbpass>] [-httpUser <httpuser>] [-httpPass <httppass>] [-help] [-verbose]

Options:
  -help       Optional, prints help message
  -dbUser     Optional, defaults to root
  -dbPass     Optional, database user password, defaults to redhat123
  -httpUser   Optional, http user, defaults to jdoe
  -httpPass   Optional, http password, defaults to jdoe123
  -port       Optional, the HTTPS port for the server to listen on, defaults to 443
  -serverCert Mandatory, server's certificate file
  -serverKey  Mandatory, server's private key certificate file
  -tangServer Mandatory, tang server location in form host:port
```

Taking into account the certificates generated in section [Certificate generation](#certificate-generation), the
server will be executed as follows:

```bash
$ ./http-server-x509-svid-parser -dbUser root -dbPass redhat12345 -httpUser jdoe -httpPass jdoe12345 -port 8887 -serverCert server_bundle.pem --serverKey server.key -tangServer env-ephemeral-b52sye-nzjnxgp5.apps.c-rh-c-eph.8p0c.p1.openshiftapps.com
...
2023/07/28 17:15:08 Connected to DB!
2023/07/28 17:15:08 Sending requests to env-ephemeral-b52sye-nzjnxgp5.apps.c-rh-c-eph.8p0c.p1.openshiftapps.com
2023/07/28 17:15:08 URL:[https://env-ephemeral-b52sye-nzjnxgp5.apps.c-rh-c-eph.8p0c.p1.openshiftapps.com]
...
```

It must be highlighted that server certificate (`server_bundle.pem`) already contains the CA certificate, so it is not necessary
to provide it to the server in an additional parameter.


## Agent certificates
The main purpose of this server application is to show how SVID in an SPIRE agent certificate can be parsed.
The agent private key and certificate is generated by the SPIRE agent once server attests its correctly.
It is not the aim of this document to document the whole SPIRE server attestation. To do so, refer to the
[References](#references)) section.

SPIRE agent generates the certificate and the keys normally in `data` directory:
```bash
$ spire-agent run -config spire-1.6.4/conf/agent/agent.conf
...
$ tree data/agent/
data/agent/
├── agent-data.json
├── agent_svid.der
├── bundle.der
└── keys.json
```

From previous directory, the files to used in client will be:
* `agent_svid.der`: This file will be used as it appears.
* `keys.json`: This file contains the private key of the agent. However, as it is not in the format that `curl` would expect,
the key has to be extracted to an `agent.key` file with the corresponding prefix and suffix. `keys.json` has next format:

```bash
$ cat data/agent/keys.json
{
        "keys": {
                "agent-svid-A": "MIGHAgE...LoNg_KeY_HeRe_123a_...LuymQw"
        }
}
```

The agent key provided to curl will be of the format:

```bash
$ cat agent.key
-----BEGIN PRIVATE KEY-----
MIGHAgE...LoNg_KeY_HeRe_123a_...LuymQw
-----END PRIVATE KEY-----

## SVID identification
To check if server is parsing SVID correctly, agent certificate can be read with `openssl` tool, so that 
Subject Alternate Name URI is obtained:

```bash
openssl x509 -inform der  -in ./agent_svid.der  --text | grep -i "Subject Alternative Name:" -A1
            X509v3 Subject Alternative Name: 
                URI:spiffe://example.org/spire/agent/aws_iid/12977789345/us-east-1/i-1234d7bdff825678
```
The URI string `spiffe://example.org/spire/agent/aws_iid/12977789345/us-east-1/i-1234d7bdff825678` is the
one that needs to be obtained in server. In case that line can be parsed, it will be demonstrated that the
information can be programmatically parsed. Next section covers how to use `curl` tool to use SPIRE agent
private key and certificate to access the HTTPS server.

## Client simulation through curl tool
Previous section showed how to obtain `curl` required files to access HTTPS server, so that it can parse
the SVID that was assigned to an agent.

For `curl` to access the HTTPS server that was started as described in Section [Server execution](#server-execution),
the command to use will be next:

```bash
$ curl --cert agent_svid.der --cert-type der --cacert ca_server_cert.pem --key ./agent.key --verbose https://localhost:8082
...
*  SSL certificate verify ok.
...
< HTTP/2 200
...
```
A description on how to get each of the files used by `curl` was performed on the previous sections.
As it can be observed in previous command, curl will dump SSL certificate verification works appropriately, and server will send
a 200 OK response with no content.
If everything works as expected HTTPS server will dump the information of the agent certificate, and print the SVID in the console:
```
2023/01/02 03:06:09
2023/01/02 03:06:18 Starting HTTPS server, port:[8082]
2023/01/02 03:06:18 Received GET request for host localhost:8082 from IP address 127.0.0.1:45738
2023/01/02 03:06:18 **************** Connection State *****************
2023/01/02 03:06:18 Version: 304
2023/01/02 03:06:18 HandshakeComplete: true
2023/01/02 03:06:18 DidResume: false
2023/01/02 03:06:18 CipherSuite: 1301
2023/01/02 03:06:18 NegotiatedProtocol: h2
2023/01/02 03:06:18 Certificate chain:
2023/01/02 03:06:18  0 s:/C=[US]/ST=[]/L=[]/O=[SPIRE]/OU=[]/CN=
2023/01/02 03:06:18    i:/C=[US]/ST=[]/L=[]/O=[SPIFFE]/OU=[]/CN=
2023/01/02 03:06:18    SAN URL:[spiffe://example.org/spire/agent/aws_iid/12977789345/us-east-1/i-1234d7bdff825678]
2023/01/02 03:06:18 **************** /Connection State ****************
```

This way, forward implementation of a proxy that uses SVID to forward agent requests can be implemented.

## References
[Configuring SPIRE for Amazon EC2 Instances](https://spiffe.io/docs/latest/deploying/configuring/#amazon-ec2-instances)\
[Install Spire Agents](https://spiffe.io/docs/latest/deploying/install-agents/)\
[Install the Spire Server](https://spiffe.io/docs/latest/deploying/install-server/)\
[How to generate certificates](https://www.golinuxcloud.com/golang-http/#Secure_Communication_over_HTTP_with_TLS_and_MTLS)

