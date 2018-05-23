package main

// Possible certificate files; stop after finding one.
var certFiles = []string{
	"/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/Gentoo etc.
	"/etc/pki/tls/certs/ca-bundle.crt",   // Fedora/RHEL
	"/etc/ssl/ca-bundle.pem",             // OpenSUSE
	"/etc/pki/tls/cacert.pem",            // OpenELEC
}
