/*
 * Copyright 2023.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

const USAGE = `
usage:

http_server_x509_svid_parser -serverCert <serverCertificateFile> -serverKey <serverPrivateKeyFile> [-port <port>] [-help]

Options:
  -help       Optional, prints help message
  -port       Optional, the HTTPS port for the server to listen on, defaults to 443
  -serverCert Mandatory, server's certificate file
  -serverKey  Mandatory, server's private key certificate file

`

const READ_TIMEOUT = 5
const WRITE_TIMEOUT = 5

// printConnState prints information of the state of the connection and peer certificates, if any
func printConnState(r *http.Request) {
	state := r.TLS
	log.Print("**************** Connection State *****************")
	log.Printf("Version: %x", state.Version)
	log.Printf("HandshakeComplete: %t", state.HandshakeComplete)
	log.Printf("DidResume: %t", state.DidResume)
	log.Printf("CipherSuite: %x", state.CipherSuite)
	log.Printf("NegotiatedProtocol: %s", state.NegotiatedProtocol)
	log.Printf("NegotiatedProtocolIsMutual: %t", state.NegotiatedProtocolIsMutual)
	log.Print("Certificate chain:")
	for i, cert := range state.PeerCertificates {
		subject := cert.Subject
		issuer := cert.Issuer
		log.Printf(" %d s:/C=%v/ST=%v/L=%v/O=%v/OU=%v/CN=%s", i, subject.Country, subject.Province,
			subject.Locality, subject.Organization, subject.OrganizationalUnit, subject.CommonName)
		log.Printf("   i:/C=%v/ST=%v/L=%v/O=%v/OU=%v/CN=%s", issuer.Country, issuer.Province,
			issuer.Locality, issuer.Organization, issuer.OrganizationalUnit, issuer.CommonName)
		for _, uri := range cert.URIs {
			log.Printf("   SAN URL:[%v]", uri)
		}
	}
	log.Print("**************** /Connection State ****************")
}

// main function
func main() {
	help := flag.Bool("help", false, "Optional, prints help information")
	port := flag.String("port", "443", "HTTPS port, defaults to 443")
	serverCert := flag.String("serverCert", "", "Mandatory, the name of the server's certificate file")
	serverKey := flag.String("serverKey", "", "Mandatory, the file name of the server's private key file")
	flag.Parse()

	if *help == true {
		fmt.Println(USAGE)
		os.Exit(0)
	} else if *serverCert == "" {
		fmt.Printf("\nPlease, provide server certification file\n%s", USAGE)
		os.Exit(1)
	} else if *serverKey == "" {
		fmt.Printf("\nPlease, provide server private key file\n%s", USAGE)
		os.Exit(2)
	}

	server := &http.Server{
		Addr:         ":" + *port,
		ReadTimeout:  READ_TIMEOUT * time.Second,
		WriteTimeout: WRITE_TIMEOUT * time.Second,
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequireAnyClientCert,
		},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received %s request for host %s from IP address %s",
			r.Method, r.Host, r.RemoteAddr)
		printConnState(r)
	})

	log.Printf("Starting HTTPS server, port:[%v]", *port)
	err := server.ListenAndServeTLS(*serverCert, *serverKey)
	if err != nil {
		log.Fatalf("Unable to start HTTPS server, error:[%v]", err)
	}
}
