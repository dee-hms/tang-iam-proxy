/*
 *
 * Copyright 2023 sarroutb@redhat.com
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom
 * the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
 * OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
)

// defaultHandler is the function that
func defaultHandler(w http.ResponseWriter, r *http.Request) {
	dump, err := httputil.DumpRequest(r, true)
	log.Println("HTTP request", r, string(dump), err)
	log.Println("HTTP TLS", r.TLS, string(r.TLS.TLSUnique))
	certs := r.TLS.PeerCertificates
	log.Println("HTTP CERTS", certs)
	w.WriteHeader(http.StatusMethodNotAllowed)
	w.Write([]byte("Hello\n"))
}

// main function
func main() {
	http.HandleFunc("/", defaultHandler)
	port := flag.Uint("p", 8083, "port to listen to")
	cert := flag.String("c", "server.crt", "certificate file")
	key := flag.String("k", "server.key", "key file")
	flag.Parse()
	fmt.Println(fmt.Sprintf("port:[%d], server certificate:[%s], server key:[%s]", *port, *cert, *key))
	sport := fmt.Sprintf(":%d", *port)
	err := http.ListenAndServeTLS(sport, *cert, *key, nil)
	if err != nil {
		fmt.Println(fmt.Sprintf("Error:%v", err))
	}
}
