# Browserless PageSigner #

A set of tools to create and use PageSigner format notarization files.

Three scripts are currently provided: (1) notarize.py (2) auditor.py (3) parse-pgsg.py

* notarize - generate notarizations of webpages 
* auditor - check the validity of a pgsg file and extract the html from it
* parse-pgsg - currently, just extracts the DER certificates from the file for verification.

More details on each below.

## 1. notarize.py ##

Intended to be run as a script.
Use the script notarize.py in src/auditee
Usage: 
```
python notarize.py [-e headers_file] [-a] www.reddit.com/r/all
``` 
(no need for https, assumed)

### Important notes on usage ###

* HTTP request headers: -e option allows you to specify an **absolute** file path to a file that
contains a set of http headers in json (not including a GET). Request types other than GET have not yet
been implemented.

* Configure the notary: if necessary, edit the \[Notary\] section of the `src/shared/tlsnotary.ini` config file with
the appropriate server IP and port. Do *not* edit the remaining fields unless you know what you are doing.

Note that currently the settings are for the main tlsnotarygroup1 pagesigner oracle. This should work fine.
Bear in mind that this oracle server rate currently limits on a per-IP basis; for high frequency runs this may cause notarization to fail.

* The -a option: this flag allows you to request a check of the oracle status via AWS queries.
If this check completes successfully (note that it will run *twice*: one for the main oracle server, then again for the signing server which holds the notarizing private key).
The recommendation is to use this check periodically, but not for every run. The reason is (a) because the oracle check takes time (a few seconds) 
and also to avoid swamping AWS with queries. For example, in a bash script you could configure this option to be applied to 1 out of 10 queries.

Please see the pagesigner-oracles repo for details on the setup of the oracle server on Amazon AWS.

* Verifying the certificate: the main disadvantage of operating outside the browser is we can't
directly reuse the browser's certificate store. For now, you can find the file pubkey1 in the
session directory, which prints the pubkey of the certificate used in hex format, and manually compare it
with that reported in your browser for the same website. Note, however, that this is a **RSA** certificate,
so you will have to make sure that you connect to the site (in the browser) with an RSA key-exchange ciphersuite.
A less clunky way of achieving this sanity check is sought.

## 2. auditor.py ##

Use this to extract html and examine it, in cases where import into the PageSigner addon is not possible.

Usage and output:

```
python auditor.py myfile.pgsg 
Notary pubkey OK
Processing data for server:  incapsula.com
Notary signature OK
Commitment hash OK
HTML decryption with correct HMACs OK.
Audit passed! You can read the html at: fullpathtohtml and check the server certificate with the data provided in: fullpathtodomainfile
```

If any of the above checks do not pass, the notarization file is **definitely** invalid.
Note that the oracle's pubkey is embedded into the code; if you don't use the tlsnotarygroup1 oracle, you'll have to change it.
To complete the checking, you should compare the contents of the created `domain_data.txt` file with the certificate public key that your browser shows for that domain.

## 3. parse-pgsg.py ##

For now this is a bare-bones script that merely outputs the certificates found in the pgsg file (which are the same
certificates that were passed over the wire during the audit) into a series of DER encoded files 0.der, 1.der ... and fullcert.der.
Note that 0.der should be the certificate of the site itself.

Usage:
```
python parse-pgsg.py myfile.pgsg
```

If you want to check their contents, it can be easily done with openssl:

```
openssl x509 -in 0.der -inform der -text -noout -fingerprint
```

This will show you cert fingerprints, common name etc, expiration date etc.