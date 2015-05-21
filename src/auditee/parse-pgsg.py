#!/usr/bin/env python
from __future__ import print_function
import tarfile
from hashlib import md5, sha1, sha256
from os.path import join
import sys, os
data_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.dirname(data_dir))
install_dir = os.path.dirname(os.path.dirname(data_dir))

def extract_audit_data(audit_filename):
    audit_data = {}
    with open(audit_filename,'rb') as f:
        header = f.read(29)
        print (header)
        if header != 'tlsnotary notarization file\n\n':
            raise Exception("Invalid file format")
        version = f.read(2)
        if version != '\x00\x01':
            raise Exception("Incompatible file version")
        audit_data['cipher_suite'] = shared.ba2int(f.read(2))
        audit_data['client_random'] = f.read(32)
        audit_data['server_random'] = f.read(32)
        audit_data['pms1'] = f.read(24)
        audit_data['pms2'] = f.read(24)
        full_cert = f.read(3)
        chain_serialized_len = shared.ba2int(full_cert)
        chain_serialized = f.read(chain_serialized_len)
        full_cert += chain_serialized
        audit_data['tlsver'] = f.read(2)
        audit_data['initial_tlsver'] = f.read(2)
        response_len = shared.ba2int(f.read(8))
        audit_data['response'] = f.read(response_len)
        IV_len = shared.ba2int(f.read(2))
        if IV_len not in [258,16]:
            print ("IV length was: ", IV_len)
            raise Exception("Wrong IV format in audit file")
        audit_data['IV'] = f.read(IV_len)
        sig_len = shared.ba2int(f.read(2))
        audit_data['signature'] = f.read(sig_len) 
        audit_data['commit_hash'] = f.read(32)
        audit_data['pubkey_pem'] = f.read(sig_len)
        
        offset = 0
        chain=[]
        while (offset < chain_serialized_len):
            l = shared.ba2int(chain_serialized[offset:offset+3])
            offset += 3
            cert = chain_serialized[offset:offset+l]
            offset += l
            chain.append(cert)
        
        audit_data['certs'] = chain
        audit_data['fullcert'] = full_cert
    return audit_data

#unpack and check validity of Python modules
def first_run_check(modname,modhash):
    if not modhash: return
    mod_dir = join(data_dir, 'python', modname)
    if not os.path.exists(mod_dir):
        print ('Extracting '+modname + '.tar.gz...')
        with open(join(data_dir, 'python', modname+'.tar.gz'), 'rb') as f: tarfile_data = f.read()
        if md5(tarfile_data).hexdigest() !=  modhash:
            raise Exception ('Wrong hash')
        os.chdir(join(data_dir, 'python'))
        tar = tarfile.open(join(data_dir, 'python', modname+'.tar.gz'), 'r:gz')
        tar.extractall()
        tar.close()
        
if __name__ == "__main__":   
    #for md5 hash, see https://pypi.python.org/pypi/<module name>/<module version>
    modules_to_load = {'rsa-3.1.4':'b6b1c80e1931d4eba8538fd5d4de1355',\
                       'pyasn1-0.1.7':'2cbd80fcd4c7b1c82180d3d76fee18c8',\
                       'slowaes':'','requests-2.3.0':'7449ffdc8ec9ac37bbcd286003c80f00'}
    for x,h in modules_to_load.iteritems():
        first_run_check(x,h)
        sys.path.append(join(data_dir, 'python', x))

    import rsa
    import pyasn1
    import requests
    from pyasn1.type import univ
    from pyasn1.codec.der import encoder, decoder
    from slowaes import AESModeOfOperation        
    import shared
    shared.load_program_config()
    shared.import_reliable_sites(join(install_dir,'src','shared'))    
    
    print (sys.argv)
    
    if (len(sys.argv)!=2):
        raise Exception("Invalid argument")
    audit_data = extract_audit_data(sys.argv[1])
    for i,c in enumerate(audit_data['certs']):
        with open(str(i)+'.der','wb') as f:
            f.write(c)
            
    with open('fullcert','wb') as f:
        f.write(shared.bi2ba(len(audit_data['fullcert']),fixed=3))
        f.write(audit_data['fullcert'])
    
            
        