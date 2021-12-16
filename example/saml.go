package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"path"
	"runtime"

	"github.com/crewjam/saml/samlsp"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/pelicaned/gothsaml"
)

func initialize() []byte {
	_, dataDir, _, ok := runtime.Caller(1)
	if !ok {
		log.Fatal("Unable to get runtime file")
	}
	dataDir = path.Dir(dataDir)
	rel := func(relPath string) string {
		return path.Join(dataDir, relPath)
	}

	spKeypair, err := tls.LoadX509KeyPair(rel("testsp-cert.pem"), rel("testsp-privkey.pem"))
	if err != nil {
		log.Fatal(err)
	}
	spKeypair.Leaf, err = x509.ParseCertificate(spKeypair.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}

	idpMetadataRaw, err := ioutil.ReadFile(rel("samltestid-metadata.xml"))
	if err != nil {
		log.Fatal(err)
	}
	idpMetadata, err := samlsp.ParseMetadata(idpMetadataRaw)
	if err != nil {
		log.Fatal(err)
	}

	samlProvider, metadata, err := gothsaml.New(spKeypair.Leaf, spKeypair.PrivateKey.(*rsa.PrivateKey), idpMetadata, "http://localhost:8080/saml/metadata", "http://localhost:8080/saml/acs", "http://localhost:8080/saml/slo", &gothsaml.AttributeMap{
		Email:     "urn:oid:0.9.2342.19200300.100.1.3",
		Name:      "urn:oid:2.16.840.1.113730.3.1.241",
		FirstName: "urn:oid:2.5.4.42",
		LastName:  "urn:oid:2.5.4.4",
		UserID:    "urn:oasis:names:tc:SAML:attribute:subject-id",
	})
	if err != nil {
		log.Fatal(err)
	}
	goth.UseProviders(samlProvider)

	return metadata
}

func main() {
	metadata := initialize()

	mux := http.DefaultServeMux
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), "provider", "saml"))
		gothic.BeginAuthHandler(w, r)
	})
	mux.HandleFunc("/saml/metadata", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/samlmetadata+xml")
		w.Write(metadata)
	})
	mux.HandleFunc("/saml/acs", func(w http.ResponseWriter, r *http.Request) {
		user, err := gothic.CompleteUserAuth(w, r)
		if err != nil {
			log.Print(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, user)
	})

	http.ListenAndServe("localhost:8080", nil)
}
