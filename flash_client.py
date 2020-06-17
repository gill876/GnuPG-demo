#!/usr/bin/env python3

from keyM.pgpier import *
import requests, hashlib, os

CLIENT_NAME = 'Pgpier Client'
CLIENT_EMAIL = 'client_pgpier@gmail.com'
CLIENT_COMMENT = 'Pgpier Client created for encrypted communication'

result = create_dir('cligpg')
if result[0] == True:
    cli_dir = result[1]
    gnupghome = create_dir('.gnupg', True, cli_dir)

    if gnupghome[0] == True:
        gnupg_dir = gnupghome[1]
        print(gnupg_dir)
        gpg = Pgpier(gnupg_dir)
    else:
        raise Exception('Could not create gnupg folder to store key')
else:
    raise Exception('Could not create client folder')


#gpg = Pgpier('/home/cargill/Documents/GnuPG-demo/keys/.gnupg')
#gpg.set_from_imp()
#gpg.set_keyid()

pubkey = "public key" #gpg.exp_pub_key()
b_hash = "public key" #pubkey

pubhash = hashlib.sha256(b_hash.encode('utf-8')).hexdigest()

data = {'pub_key': pubkey, 'hash': pubhash}

url = 'http://0.0.0.0:8080/api/key'
msg = 'hello world!'

#json = jsonify.jsonify(data)

x = requests.post(url, data = data)

y = requests.get(url)

print(y.content.decode('utf-8'))

print(x)