package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.LUTC)
	log.Printf("started")
	defer log.Printf("finished")

	roots, err := loadSystemRoots()
	if err != nil {
		log.Fatalf("could not load system root certificates: %s", err)
	}
	log.Printf("loaded roots")

	host := os.Args[1]

	// Firstly, fetch all certificates from the given host while entirely
	// ignoring verification.
	dialer := net.Dialer{
		Timeout: 10 * time.Second,
	}
	conn, err := tls.DialWithDialer(&dialer, "tcp", host, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Fatalf("Failed to connect to domain %q: %s", host, err)
	}
	defer conn.Close()

	log.Printf("connected to host")

	// For each peer certificate, collect all IssuingCertificateURLs and
	// fetch them (TODO: in parallel?)
	peerCerts := conn.ConnectionState().PeerCertificates

	certs := []*x509.Certificate{}
	for _, cert := range peerCerts {
		for _, url := range cert.IssuingCertificateURL {
			if c, err := fetchCert(url); err == nil {
				certs = append(certs, c)
			}
		}
	}

	// For each root and peer, print them as PEM to stdout
	var buf bytes.Buffer
	for _, arr := range [][]*x509.Certificate{roots, certs} {
		for _, cert := range arr {
			block := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}
			if err := pem.Encode(&buf, block); err != nil {
				log.Fatalf("error marshalling as PEM: %s", err)
			}
		}
	}

	io.Copy(os.Stdout, &buf)
}

func fetchCert(url string) (*x509.Certificate, error) {
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("failed fetching certificate %s: %s", url, err)
		return nil, err
	}
	defer resp.Body.Close()

	c, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("failed fetching certificate %s: %s", url, err)
		return nil, err
	}

	cert, err := x509.ParseCertificate(c)
	if err != nil {
		log.Printf("failed to parse certificate %s: %s", url, err)
		return nil, err
	}

	log.Printf("fetched certificate: %s", url)
	return cert, nil
}

func parseFromPem(pemCerts []byte) []*x509.Certificate {
	ret := []*x509.Certificate{}
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		ret = append(ret, cert)
	}

	return ret
}
