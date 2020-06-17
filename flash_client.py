#!/usr/bin/env python3

from keyM.pgpier import *
import requests, hashlib

CLIENT_NAME = 'Pgpier Client'
CLIENT_EMAIL = 'client_pgpier@gmail.com'
CLIENT_COMMENT = 'Pgpier Client created for encrypted communication'

gpg = Pgpier('/home/cargill/Documents/GnuPG-demo/keys/.gnupg')
gpg.set_from_imp()
gpg.set_keyid()

pubkey = gpg.exp_pub_key()
b_hash = pubkey

pubhash = hashlib.sha256(b_hash.encode('utf-8')).hexdigest()

data = {'pub_key': pubkey, 'hash': pubhash}

url = 'http://0.0.0.0:8080/api/key'
msg = 'hello world!'

#json = jsonify.jsonify(data)

x = requests.post(url, data = data)

y = requests.get(url)

print(y.content.decode('utf-8'))

print(x)