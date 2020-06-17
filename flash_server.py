#!/usr/bin/env python3

from flask import Flask, session, request
app = Flask(__name__)

@app.route('/')
def hello():
    return "Hello World!"

@app.route('/api/recv', methods=['POST'])
def recv():
    if request.method == 'POST':
        print(request.data)
        print("POST method")
    print("Inside /api/recv function")
    return "hello world"

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=8080)