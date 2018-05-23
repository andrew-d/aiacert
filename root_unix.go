package main

import (
	"crypto/x509"
	"io/ioutil"
	"os"
)

// Possible directories with certificate files; stop after successfully
// reading at least one file from a directory.
var certDirectories = []string{
	"/etc/ssl/certs",               // SLES10/SLES11, https://golang.org/issue/12139
	"/system/etc/security/cacerts", // Android
}

func loadSystemRoots() ([]*x509.Certificate, error) {
	var firstErr error
	for _, file := range certFiles {
		data, err := ioutil.ReadFile(file)
		if err == nil {
			return parseFromPem(data), nil
		}
		if firstErr == nil && !os.IsNotExist(err) {
			firstErr = err
		}
	}

	roots := []*x509.Certificate{}
	for _, directory := range certDirectories {
		fis, err := ioutil.ReadDir(directory)
		if err != nil {
			if firstErr == nil && !os.IsNotExist(err) {
				firstErr = err
			}
			continue
		}
		rootsAdded := false
		for _, fi := range fis {
			data, err := ioutil.ReadFile(directory + "/" + fi.Name())
			if err == nil {
				curr := parseFromPem(data)
				if len(curr) > 0 {
					roots = append(roots, curr...)
					rootsAdded = true
				}
			}
		}
		if rootsAdded {
			return roots, nil
		}
	}

	return nil, firstErr
}
