#!/usr/bin/env python3

import os
from socket import socket, gethostbyname, gethostname, AF_INET, SOCK_DGRAM
from keyM import pgpier as key

def Main():

    host = gethostbyname(gethostname()) #Server ip
    port = 4000

    s = socket(AF_INET, SOCK_DGRAM)
    s.bind((host, port))

    print("Server Started")
    while True:
        data, addr = s.recvfrom(1024)
        data = data.decode('utf-8')
        if data == "close":
            break
        print("Message from: " + str(addr))
        print("From connected user: " + data)
        data = data.upper()
        print("Sending: " + data)
        s.sendto(data.encode('utf-8'), addr)
    s.close()

if __name__=='__main__':
    Main()

print('basename:    ', os.path.basename(__file__))
print('dirname:     ', os.path.dirname(__file__))

EXEC_DIR = os.path.dirname(os.path.realpath(__file__))
print(os.path.realpath(__file__))
print(EXEC_DIR)

ROOT_DIR = os.path.abspath(os.path.join(os.path.abspath(os.path.join(EXEC_DIR, os.pardir)), os.pardir))

print(ROOT_DIR)

print(os.path.join(os.path.abspath(os.path.join(EXEC_DIR, os.pardir)), os.pardir))

print(os.path.abspath(os.path.join(EXEC_DIR, os.pardir)))

print(os.pardir)
print("************")
print(key.key_dir("keys"))