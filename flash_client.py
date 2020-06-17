#!/usr/bin/env python3

from keyM.pgpier import *
import requests

gpg = Pgpier('/home/cargill/Documents/GnuPG-demo/keys/.gnupg')
gpg.set_from_imp()
gpg.set_keyid()

pubkey = gpg.exp_pub_key()

print(pubkey)

url = 'http://0.0.0.0:8080/api/recv'
msg = 'hello world!'

x = requests.post(url, data = pubkey)

print(x)