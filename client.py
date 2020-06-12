#!/usr/bin/env python3

from socket import socket, gethostbyname, gethostname, AF_INET, SOCK_DGRAM

def Main():

    host= gethostbyname(gethostname()) #client ip
    port = 4004

    server = ('0.0.0.0', 4000)

    s = socket(AF_INET, SOCK_DGRAM)
    s.bind((host,port))

    message = input("-> ")
    while message !='q':
        s.sendto(message.encode('utf-8'), server)
        data, addr = s.recvfrom(1024)
        data = data.decode('utf-8')
        print("Received from server: " + data)
        message = input("-> ")
        if message == 'close':
            s.sendto(message.encode('utf-8'), server)
            break
    s.close()
Main()