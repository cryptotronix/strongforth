package main

/*
#cgo CFLAGS: -g -Wall -I. -I../lib/core -I/usr/lib/cryptoauthlib -I/usr/include/cryptoauthlib
#cgo LDFLAGS: -fsanitize=address -L. -lcryptoauth -lm -lstf_server
#include "strongforth.h"
#include "cryptoauthlib.h"
*/
import "C"

import (
	//"crypto/tls"
	//"crypto/x509"
	"io"
	//"io/ioutil"
	"log"
	"net/http"
	"bytes"
)

type (
	Eval_Resp C.struct_stf_eval_resp
)

func index(w http.ResponseWriter, r *http.Request) {

	if r.URL.Path != "/" {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	switch r.Method {
		case "POST":
			buf := new(bytes.Buffer)
			buf.ReadFrom(r.Body)
			bodyStr := buf.String()
			log.Printf("POST \"%v\"", bodyStr)
			var stfresp Eval_Resp
			stfresp = (Eval_Resp)(C.stf_eval(C.CString(bodyStr)))
			retstr := C.GoString(C.stf_get_retbuf())

			log.Printf("stf_eval rc: %v", stfresp.rc)
			log.Printf("stf_eval stf_status: %v", stfresp.stf_status)

			if stfresp.rc != 0 {
				log.Printf("stf_eval failed")
				http.Error(w, "Server Error", http.StatusInternalServerError)
			}

			log.Printf("stf_eval retbuf: \"%v\"", retstr)

			if len(retstr) == 0 {
				w.WriteHeader(http.StatusNoContent)
			}
			io.WriteString(w, retstr)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func main() {

	//caCert, _ := ioutil.ReadFile("ca.crt")
	//caCertPool := x509.NewCertPool()
	//caCertPool.AppendCertsFromPEM(caCert)

	//tlsConfig := &tls.Config{
	//	ClientCAs:  caCertPool,
	//	ClientAuth: tls.RequireAndVerifyClientCert,
	//}
	//tlsConfig.BuildNameToCertificate()

	status := C.stf_init(C.CString("../forth/strongforth.zf"), nil);

	if status != C.ATCA_SUCCESS {
		log.Printf("uh oh")
	}

	server := &http.Server{
		Addr:      ":8080",
		//TLSConfig: tlsConfig,
	}

	// http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
	// 	io.WriteString(w, "Hello, mTLS!\n")
	// })

	http.HandleFunc("/", index)

	//log.Fatal(server.ListenAndServeTLS("cert.pem", "key.pem"))
	log.Fatal(server.ListenAndServe())

}
