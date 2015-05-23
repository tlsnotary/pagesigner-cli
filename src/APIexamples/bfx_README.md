HOW TO USE:
===========
        
First, you need an API key and API secret from Bitfinex,
available on the website. These are alphanumeric strings.
Write them as the first two lines in a file anywhere on disk.
Then, run the script as:

    python bitfinexAPI.py absolute-path-to-APIkeyfile absolute-path-to-new-headers-file

where the first argument is the full path for the API key file you created earlier,
and the second argument is a new file location in which the headers can be stored
(it can be anywhere, but make sure it's the **absolute** path).

For now, the script will record a proof of the balance of the account owner, which 
can be found in `src/auditee/sessions/<timestamp>/commit/html-1`. The data is seen
at the bottom of the file in json.

This script is designed so it can be called from a shell script or similar, perhaps
at regular intervals. Usage is up to your imagination.

Notes
=====
Still primitive. See the TODOs in the Python script, and read the API docs on bitfinex.com.