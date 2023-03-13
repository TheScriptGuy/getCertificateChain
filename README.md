# :closed_lock_with_key::closed_lock_with_key::closed_lock_with_key: Get the Certificate Chain :closed_lock_with_key::closed_lock_with_key::closed_lock_with_key:

Getting the certificate chain for a hostname should not be difficult!

Sometimes websites do not present the full chain (against RFC recommendations) which means it's hard to find the certificate chain and troubleshoot.

This script will attempt to use the breadcrumbs that are left by the certificate to build the chain and output it into files.

It's worked on publicly available websites (at least the ones I've tested). Happy to troubleshoot if an error pops up.


# Requirements
```bash
$ python3 -m pip install re cryptography argparse ssl
```

# :runner: How to run
To get the arguments available `python3 getCertChain.py --help`. Should present information like this:
```bash
$ python3 getCertChain.py --help
usage: getCertChain.py [-h] [--hostname HOSTNAME] [--removeCertificateFiles] [--getCAcertPEM]

Get Certificate Chain v0.01

optional arguments:
  -h, --help            show this help message and exit
  --hostname HOSTNAME   The hostname:port pair that the script should connect to. Defaults to www.google.com:443.
  --removeCertificateFiles
                        Remove the certificate files in current working directory (*.crt, *.pem).
  --getCAcertPEM        Get cacert.pem from curl.se website to help find Root CA.
```

# :books: Examples
To get the certificate chain for www.google.com
```bash
$ python3 getCertChain --hostname www.google.com
$
```
It by default will not display any output (unless it struggles to find the Root CA).

To see the files it created (from where the script ran):
```bash
$ ls -l
total 28
-rw-r--r-- 1 gituser gituser  1911 Mar 12 16:38 0-gts-root-r1.crt
-rw-r--r-- 1 gituser gituser  1996 Mar 12 16:38 1-gts-ca-1c3.crt
-rw-r--r-- 1 gituser gituser  1631 Mar 12 16:38 2-www.google.com.crt
-rw-r--r-- 1 gituser gituser 13385 Mar 12 16:36 getCertChain.py
```
If you notice the prefix of each new file that was created (i.e. 0-, 1-, 2-) this is the order of the chain with 
* `0-` being the Root CA
* `1-` being the intermediate CA
* `2-` being the endpoint/website certificate

The rest of the file name is deduced from the commonName in the certificate.

On some occasions, the intermediate CA does not present an Authority Information Access field (AIA) with a URI on where to get the file from. 

To help build the chain, we need some `external` help - leveraging the `cacert.pem` file from `curl.se` website.
This is the url: :link: `https://curl.se/ca/cacert.pem`

To get the `cacert.pem` file as part of the connection from `--hostname` argument:
```bash
$ python3 getCertChain.py --hostname www.google.com --getCAcertPEM
```

You could also run it by itself:
```bash
$ python3 getCertChain.py --getCAcertPEM
```

# :dash::hole: Clean up all the files
```bash
$ python3 getCertChain.py --removeCertificateFiles
Removing file 1-gts-ca-1c3.crt
Removing file 2-www.google.com.crt
Removing file 0-gts-root-r1.crt
Removing file cacert.pem
```

# :warning: MitM proxies/services
Given the way MitM proxies and decryption services work, this tool is not intended to be used behind devices that perform SSL/TLS decryption as those devices strip the `Authority Information Access` (AIA), and alter the `Subject Key Identifier` (SKI) and `Authority Key Identifier` (AKI) fields.
