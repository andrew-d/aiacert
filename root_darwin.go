package main

import (
	"crypto/x509"
	"os/exec"
)

var certFiles = []string{}

func getRootCerts() ([]*x509.Certificate, error) {
	cmd := exec.Command("/usr/bin/security", "find-certificate", "-a", "-p", "/System/Library/Keychains/SystemRootCertificates.keychain")
	data, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	return parseFromPem(data), nil
}
