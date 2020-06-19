#!/usr/bin/env python3

from keyM.pgpier import *
from flask import Flask, session, request, jsonify, g
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()

SERVER_NAME = 'Pgpier Server'
SERVER_EMAIL = 'server_pgpier@gmail.com'
SERVER_COMMENT = 'Pgpier Server created for encrypted communication'

#####
result = create_dir('svrgpg')
if result[0] == True:
    svr_dir = result[1]
    gnupghome = create_dir('.gnupg', True, svr_dir)

    if gnupghome[0] == True:
        gnupg_dir = gnupghome[1]
        app.config['GPG'] = gnupg_dir
        print(gnupg_dir)
        gpg = Pgpier(gnupg_dir)
    else:
        raise Exception('Could not create gnupg folder to store key')
else:
    raise Exception('Could not create server folder')

set_values = gpg.set_from_imp()

if not set_values:
    print("Generating key pairs")
    gpg.key_pair(SERVER_EMAIL, SERVER_NAME, SERVER_COMMENT)
    gpg.exp_main()

gpg.set_keyid()

public_key = gpg.exp_pub_key()
#####

@app.route('/')
def hello():
    return "Hello World!"

@app.route('/api/key', methods=['POST', 'GET'])
def key():
    if request.method == 'POST':
        client_key = request.form['client_key']
        key_hash = request.form['key_hash']

        client_email = request.form['client_email']
        email_hash = request.form['email_hash']

        tohash = client_key
        hashed = hashlib.sha256(tohash.encode('utf-8')).hexdigest()

        tohash = client_email
        hashed2 = hashlib.sha256(tohash.encode('utf-8')).hexdigest()
        print(hashed == key_hash and hashed2 == email_hash)
        if hashed == key_hash:
            g.client_key = client_key
            g.client_email = client_email
            print("from session", g.client_email)
            
            gpg.imp_pub_key(g.client_key)
            #print(gpg.list_pub_keys())

        print("POST method")
    if request.method == 'GET':
        session['nonce'] = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()

        server_key = gpg.exp_pub_key()
        server_email = SERVER_EMAIL
        server_nonce = session['nonce']
        client_email = g.client_email

        client_fingerprint = gpg.email_to_key(client_email)

        encrypted_nonce = gpg.encrypt_data(server_nonce, client_fingerprint)

        data = {'server_email': server_email, 'server_key': server_key, 'encrypted_nonce': encrypted_nonce}
        return jsonify(data=data)
    print("Inside /api/recv function")
    return "hello world"

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=8080)