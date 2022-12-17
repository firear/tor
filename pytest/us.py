#!/usr/bin/env python
import socket
address = ('127.0.0.1', 10000)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(address)
while True:
    data, addr = s.recvfrom(2048)
    if not data:
        break
    print(int.from_bytes(data[:4], 'little'), len(data))
    s.sendto(data, addr)
s.close()
