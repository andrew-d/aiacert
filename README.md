# aiacert

Demonstration of fetching certificates from the "Authority Information Access"
extension in X.509 certificates.

The "Authority Information Access" (AIA) extension contains information about
the issuer of the certificate. This extension helps fetch intermediate
certificates from the issuing certification authority, which is especially
helpful in the case where a server does not provide intermediate certificates.

Without following AIA: certificate verification will fail because there's no
chain between the presented (leaf) certificate and a verified root. If we
follow AIA certificate links, however, we can build a valid certificate chain
between the leaf certificate, the fetched intermediate certificate(s), and a
verified root.

This repository contains an example of how to fetch AIA certificates from a TLS
server.
