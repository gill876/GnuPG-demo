#!/usr/bin/env python3

from keyM.pgpier import *
import requests, hashlib, os, json

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

set_values = gpg.set_from_imp()

if not set_values:
    print("Generating key pairs")
    gpg.key_pair(CLIENT_EMAIL, CLIENT_NAME, CLIENT_COMMENT)
    gpg.exp_main()
#gpg = Pgpier('/home/cargill/Documents/GnuPG-demo/keys/.gnupg')
#gpg.set_from_imp()
gpg.set_keyid()

public_key = gpg.exp_pub_key()

pubkey = public_key

tohash = pubkey
pubhash = hashlib.sha256(tohash.encode('utf-8')).hexdigest()

tohash = CLIENT_EMAIL
ehash = hashlib.sha256(tohash.encode('utf-8')).hexdigest()

data = {'client_key': pubkey, 'key_hash': pubhash, 'client_email': CLIENT_EMAIL, 'email_hash': ehash}

url = 'http://0.0.0.0:8080/api/key'
msg = 'hello world!'

#x = requests.post(url, data = data)
#print(x)

y = requests.get(url)

data = y.json()

print(data['data']['message'])

#print(y.content.decode('utf-8'))