gocerts
=======

Tired of using Openssl and various automation/scripts to build certificates and keys for my test labs, gocerts was the answer.

Based on a simple yaml file ```gocerts.yaml``` (sample included), gocerts will generate a CA and all certificates based on given CNs and SANs (DNS and/or IP).

Default subject values for certificates and CA are: ```O=SCC,L=Nanterre,C=FR```

Usage: ```./gocerts``` with the ```gocerts.yaml``` file next to the binary.

NB: gocerts also generate all PFX/PCKS12 files containing key and certificate chain for convenience with the default password ```changeit```
