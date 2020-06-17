#!/usr/bin/env python3

from keyM.pgpier import *
from flask import Flask, session, request
import hashlib

app = Flask(__name__)

@app.route('/')
def hello():
    return "Hello World!"

@app.route('/api/key', methods=['POST', 'GET'])
def key():
    if request.method == 'POST':
        _key = request.form['pub_key']
        _hash = request.form['hash']
        tohash = _key
        hashed = hashlib.sha256(tohash.encode('utf-8')).hexdigest()
        print(hashed == _hash)
        print("POST method")
    if request.method == 'GET':
        return 'hello there, I\'m from the server'.encode('utf-8')
    print("Inside /api/recv function")
    return "hello world"

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=8080)