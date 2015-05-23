from __future__ import print_function
import requests
import json
import base64
import hashlib
import time
import hmac
import sys
from subprocess import check_output
def build_headers(header_file, bfx_data):

    payloadObject = {
            'request':bfx_data['call'],
            #nonce must be strictly increasing
            'nonce':str(long(time.time()*1000000)),  
            'options':{}
    }
    payload_json = json.dumps(payloadObject)
    payload = base64.b64encode(payload_json)
    m = hmac.new(bfx_data['secret'], payload, hashlib.sha384)
    m = m.hexdigest()
    headers = {
          'X-BFX-APIKEY' : bfx_data['key'],
          'X-BFX-PAYLOAD' : payload,
          'X-BFX-SIGNATURE' : m
    }
    with open(header_file,'wb') as f:
        f.write(json.dumps(headers))
    

def run_pagesigner(header_file, bfx_data):
    url = bfx_data['url']+bfx_data['call']
    #TODO tidy up file paths
    r = check_output(['python','../auditee/notarize.py','-e',header_file,url])
    #TODO flag success/failure
    print ("PageSigner notarization output: \n", r)
        
if __name__ == "__main__":
    bitfinexURLroot = 'api.bitfinex.com'
    #TODO: the first obvious extension is to 
    #add other API queries other than balance    
    bitfinexURLAPIcall = '/v1/balances'
    if len(sys.argv) != 3:
        print ("wrong args, see bfx_README.md")
        exit(1)
    #TODO use optparse or similar, make input more flexible, including file paths
    #and other options
    with open(sys.argv[1],'rb') as f:
        bitfinexKey = f.readline().rstrip()
        bitfinexSecret = f.readline().rstrip()
    bfx_data = {'url': bitfinexURLroot, 'call': bitfinexURLAPIcall, 
                'key':bitfinexKey, 'secret': bitfinexSecret}
    build_headers(sys.argv[2], bfx_data)
    run_pagesigner(sys.argv[2], bfx_data)