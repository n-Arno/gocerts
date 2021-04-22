gocerts
=======

Tired of using Openssl and various automation/scripts to build certificates and keys for my test labs, gocerts was the answer.

Based on a simple yaml file ```gocerts.yaml``` (sample included), gocerts will generate a CA and all certificates based on given CNs and SANs (DNS and/or IP).

Default subject values for certificates and CA are: ```O=SCC,L=Nanterre,C=FR```

Usage: ```./gocerts``` with the ```gocerts.yaml``` file next to the binary.

NB: gocerts also generate all PFX/PCKS12 files containing key and certificate chain for convenience with the default password ```changeit```

v2.0
----

New in version 2.0: gocerts can now read an existing CA from a pfx file containing key and certificate to generate the certificates.

Usage ```./gocerts ca.pfx```. You will be prompted for the pfx file password. Remember to use winpty if using mingw/msys bash under windows to be able to read from stdin.

Classic usage still valid (just don't provide a file name as argument).

v3.0
----

New in version 3.0: gocerts can now sign CSR provided as is. Only the certificate is returned in this case.

To do this, add a ```requests``` block (optional) in ```gocerts.yaml```. 
