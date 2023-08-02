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
	"encoding/base64"
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
  -verbose    Optional, be more verbose

`

// Read/Write timeouts
const HTTP_READ_TIMEOUT = 5 * time.Second
const HTTP_WRITE_TIMEOUT = 5 * time.Second

// EE well known URL
const EE_URL = "/api/dee-hms/"

// Global DB variable
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

// getSpiffeId returns spiffe id parsed from Subject Alternate Names
func getSpiffeId(r *http.Request) (string, error) {
	state := r.TLS
	for _, cert := range state.PeerCertificates {
		for _, uri := range cert.URIs {
			if strings.HasPrefix(uri.String(), "spiffe://") {
				return uri.String(), nil
			}
		}
	}
	return "", fmt.Errorf("getSpiffeId: no spiffeId found")
}

// getWorkspace returns the ID (A.K.A. workspace) corresponding to an Spiffe ID
func getWorkspace(spiffeId string) (string, error) {
	var workspace string
	row := db.QueryRow("SELECT tang_workspace FROM bindings WHERE spiffe_id = ?", spiffeId)
	if err := row.Scan(&workspace); err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("getWorkspace %s: no workspace found", spiffeId)
		}
		return "", fmt.Errorf("getWorkspace %s: %v", spiffeId, err)
	}
	return workspace, nil
}

// AppData struct allows not having to pass user/password everywhere
type AppData struct {
	user string
	password string
	verbose bool
}

// SimpleProxy relevant information
type SimpleProxy struct {
	Proxy *httputil.ReverseProxy
	appData *AppData
	targetHost string
}

// newProxy takes target host and creates a reverse proxy
func newProxy(targetHost string, appData* AppData) (*SimpleProxy, error) {
	url, err := url.Parse(targetHost)
	if err != nil {
		return nil, err
	}
	log.Printf("URL:[%s]", url);
	s := &SimpleProxy{httputil.NewSingleHostReverseProxy(url), appData, targetHost}
	return s, nil
}

// basicAuth function encodes user/password in Base64 format
func basicAuth(username string, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// addUserPassword encodes Authorization header with user and password
func addUserPassword(req *http.Request, audata AppData) {
	req.Header.Add("Authorization", "Basic " + basicAuth(audata.user, audata.password))
}

// ServeHTTP is request processing function
func (s *SimpleProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received %s request for host %s from IP address %s",
		r.Method, r.Host, r.RemoteAddr)
	printConnState(r)
	spiffeId, err := getSpiffeId(r)
	if err != nil {
		log.Print(err)
		http.Error(w, "not authorized!!", http.StatusUnauthorized)
	}
	workspace, err := getWorkspace(spiffeId)
	if err != nil {
		log.Print(err)
		http.Error(w, "not authorized!!", http.StatusUnauthorized)
	}
	log.Printf("tangWorkspace: %s", workspace)

	// modify request by adding workspace
	originalPath := r.URL.Path
	// if the original path contains the well known EE path (/api/dee-hms/)
	// set workspace after it
	if strings.Contains(originalPath, EE_URL) {
		suffix := strings.ReplaceAll(originalPath, EE_URL, "")
		r.URL.Path = fmt.Sprintf("%s%s/%s", EE_URL, workspace, suffix)
	} else {
		r.URL.Path = fmt.Sprintf("/%s%s", workspace, originalPath)
	}
	addUserPassword(r, AppData{user: s.appData.user, password: s.appData.password})
	noHttpsTargetHost := strings.ReplaceAll(s.targetHost, "https://", "")
	r.Header.Add("Host", noHttpsTargetHost)
	log.Printf("URL Path %s\n", r.URL.Path)
	log.Printf("Original Path %s\n", originalPath)
	for k, v := range r.Header {
		log.Printf("Header[%s]:%s", k, v)
	}
	r.URL.Scheme = "https"
	r.URL.Host = noHttpsTargetHost
	r.Host = noHttpsTargetHost
	if s.appData.verbose {
		sr, e := httputil.DumpRequestOut(r, false /*no body to print*/)
		if e == nil {
			log.Printf("RequestOut:[%s]", string(sr))
		}
		sr, e = httputil.DumpRequest(r, false /*no body to print*/)
		if e == nil {
			log.Printf("Request:[%s]", string(sr))
		}
	}

	s.Proxy.ServeHTTP(w, r)
}

// main function
func main() {
	var err error
	help := flag.Bool("help", false, "Optional, prints help information")
	port := flag.String("port", "443", "HTTPS port, defaults to 443")
	dbUser := flag.String("dbUser", "root", "DB user, defaults to root")
	dbPass := flag.String("dbPass", "", "DB Password, defaults to none")
	httpUser := flag.String("httpUser", "jdoe", "HTTP Authentication User, defaults to jdoe")
	httpPass := flag.String("httpPass", "jdoe1123", "HTTP Authentication Password, defaults to jdoe123")
	serverCert := flag.String("serverCert", "", "Mandatory, the name of the server's certificate file")
	serverKey := flag.String("serverKey", "", "Mandatory, the file name of the server's private key file")
	tangServer := flag.String("tangServer", "", "Mandatory, the server:port for the backend tang server")
	verbose := flag.Bool("verbose", false, "Optional, prints more request/response information")
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
	log.Printf("Sending requests to %s", *tangServer)

	// get a proxy
	proxy, err := newProxy(fmt.Sprintf("https://%s", *tangServer), &AppData{*httpUser, *httpPass, *verbose})
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
