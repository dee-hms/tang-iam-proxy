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
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

const USAGE = `
usage:

http_server_x509_svid_parser -serverCert <serverCertificateFile> -serverKey <serverPrivateKeyFile> [-port <port>] [-help]

Options:
  -help       Optional, prints help message
  -dbUser     Optional, defaults to root
  -dbPass     Optional, database user password, defualts to redhat123
  -port       Optional, the HTTPS port for the server to listen on, defaults to 443
  -serverCert Mandatory, server's certificate file
  -serverKey  Mandatory, server's private key certificate file
  -tangServer Mandatory, tang server location in form host:port

`

const HTTP_READ_TIMEOUT = 5
const HTTP_WRITE_TIMEOUT = 5

var db *sql.DB

// printConnState prints information of the state of the connection and peer certificates, if any
func printConnState(r *http.Request) {
	state := r.TLS
	log.Print("**************** Connection State *****************")
	log.Printf("Version: %x", state.Version)
	log.Printf("HandshakeComplete: %t", state.HandshakeComplete)
	log.Printf("DidResume: %t", state.DidResume)
	log.Printf("CipherSuite: %x", state.CipherSuite)
	log.Printf("NegotiatedProtocol: %s", state.NegotiatedProtocol)
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

func getSpiffeId(r *http.Request) (string, error) {
	state := r.TLS
	for _, cert := range state.PeerCertificates {
		for _, uri := range cert.URIs {
			if strings.HasPrefix(uri.String(), "spiffe://") {
				return uri.String(), nil
			}
		}
	}
	return "", fmt.Errorf("getSpiffeId %s: no spiffeId found")
}

func getTangId(spiffeId string) (string, error) {
	var tangId string
	row := db.QueryRow("SELECT tang_id FROM bindings WHERE spiffe_id = ?", spiffeId)
	if err := row.Scan(&tangId); err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("getTangId %s: no tangId found", spiffeId)
		}
		return "", fmt.Errorf("getTangId %s: %v", spiffeId, err)
	}
	return tangId, nil
}

type SimpleProxy struct {
	Proxy *httputil.ReverseProxy
}

// NewProxy takes target host and creates a reverse proxy
func NewProxy(targetHost string) (*SimpleProxy, error) {
	url, err := url.Parse(targetHost)
	if err != nil {
		return nil, err
	}

	s := &SimpleProxy{httputil.NewSingleHostReverseProxy(url)}
	return s, nil
}

func (s *SimpleProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received %s request for host %s from IP address %s",
		r.Method, r.Host, r.RemoteAddr)
	printConnState(r)
	spiffeId, err := getSpiffeId(r)
	if err != nil {
		log.Print(err)
		http.Error(w, "not authorized!!", http.StatusUnauthorized)
	}
	tangId, err := getTangId(spiffeId)
	if err != nil {
		log.Print(err)
		http.Error(w, "not authorized!!", http.StatusUnauthorized)
	}
	log.Printf("tangId: %s", tangId)

	// modify request by adding tangId
	originalPath := r.URL.Path
	r.URL.Path = fmt.Sprintf("/%s/%s", tangId, originalPath)
	r.Header.Set("X-Tang-Id", tangId)
	r.URL.Scheme = "http"

	s.Proxy.ServeHTTP(w, r)
	log.Printf("received response from tang server")
}

// main function
func main() {
	var err error
	help := flag.Bool("help", false, "Optional, prints help information")
	port := flag.String("port", "443", "HTTPS port, defaults to 443")
	dbUser := flag.String("dbUser", "root", "DB user, defaults to root")
	dbPass := flag.String("dbPass", "", "DB Password, defaults to none")
	serverCert := flag.String("serverCert", "", "Mandatory, the name of the server's certificate file")
	serverKey := flag.String("serverKey", "", "Mandatory, the file name of the server's private key file")
	tangServer := flag.String("tangServer", "", "Mandatory, the server:port for the backend tang server")
	flag.Parse()

	if *help {
		fmt.Print(USAGE)
		os.Exit(0)
	} else if *serverCert == "" {
		fmt.Printf("\nPlease, provide server certification file\n%s", USAGE)
		os.Exit(1)
	} else if *serverKey == "" {
		fmt.Printf("\nPlease, provide server private key file\n%s", USAGE)
		os.Exit(2)
	}

	// Get a database handle.
	dbConnectString := fmt.Sprintf("%s:%s@/tang_bindings", *dbUser, *dbPass)
	db, err = sql.Open("mysql", dbConnectString)
	if err != nil {
		log.Fatal(err)
	}

	pingErr := db.Ping()
	if pingErr != nil {
		log.Fatal(pingErr)
	}
	log.Printf("Connected to DB!")

	// get a proxy
	proxy, err := NewProxy(fmt.Sprintf("http://%s", *tangServer))
	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Addr:         ":" + *port,
		ReadTimeout:  HTTP_READ_TIMEOUT * time.Second,
		WriteTimeout: HTTP_WRITE_TIMEOUT * time.Second,
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequireAnyClientCert,
		},
	}

	http.Handle("/", proxy)

	log.Printf("Starting HTTPS server, port:[%v]", *port)
	log.Fatal(server.ListenAndServeTLS(*serverCert, *serverKey))
}
