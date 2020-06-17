#!/usr/bin/env python3

import requests

url = 'http://0.0.0.0:8080/api/recv'
msg = 'hello world!'

x = requests.post(url, data = msg)

print(x)