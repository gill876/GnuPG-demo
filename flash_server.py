#!/usr/bin/env python3

from keyM.pgpier import *
from flask import Flask, session, request
import hashlib

SERVER_NAME = 'Pgpier Server'
SERVER_EMAIL = 'server_pgpier@gmail.com'
SERVER_COMMENT = 'Pgpier Server created for encrypted communication'

app = Flask(__name__)
app.config['SECRET_KEY'] = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()

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
            session['client_key'] = client_key
            session['client_email'] = client_email
        print("POST method")
    if request.method == 'GET':
        return 'hello there, I\'m from the server'.encode('utf-8')
    print("Inside /api/recv function")
    return "hello world"

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=8080)