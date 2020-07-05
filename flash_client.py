#!/usr/bin/env python3

from keyM.pgpier import *
import requests, hashlib, os, random, string

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

s = requests.Session()

url = 'http://0.0.0.0:8080/api/key'
msg = 'hello world!'

x = requests.post(url, data = data)
#print(x)

y = s.get(url, params={'email': CLIENT_EMAIL})

data = y.json()
#print(data)

encrypted_nonce = data['data']['encrypted_nonce']
passphrase = gpg.passphrase
nonce = gpg.decrypt_data(encrypted_nonce, passphrase)

print("Server nonce: ", nonce)

server_email = data['data']['server_email']
server_key = data['data']['server_key']

gpg.imp_pub_key(server_key)
server_fingerprint = gpg.email_to_key(server_email)
gpg.trust_key(server_fingerprint, 'TRUST_ULTIMATE')

################

#print(y.content.decode('utf-8'))
url = 'http://0.0.0.0:8080/api/validation'

hashed = hashlib.sha256(nonce.encode('utf-8')).hexdigest()
message = nonce

symmetric_key = gpg.gen_symm_key()
print("symmetric key: ", symmetric_key)

mdigest = hashed + '.' + message

encrypted_mdigest = gpg.symmetric_encrypt(mdigest, symmetric_key)

encrypted_symm_key = gpg.encrypt_data(symmetric_key, server_fingerprint)

data = {'encrypted_mdigest': encrypted_mdigest, 'encrypted_symm_key': encrypted_symm_key}

x = s.post(url, data=data)
print(x)