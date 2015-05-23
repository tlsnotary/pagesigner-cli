# Browserless PageSigner

Intended to be run as a script.
Use the script notarize.py in src/auditee
Syntax: `python notarize.py [-e headers_file] [-a] www.reddit.com/r/all` (no need for https, assumed)

Important notes on usage
========================

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


