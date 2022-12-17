#!/usr/bin/env python
import socket
addr = ('127.0.0.1', 9999)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
i = 0
while True:
    data = int.to_bytes(i, 4, 'little')
    if not data:
        break
    data += b'1' * 1000
    s.sendto(data, addr)
    recvs = s.recv(2048)
    if int.from_bytes(data[:4], 'little') != i:
        print('error:%d'%(i))
        break
    i += 1
    if i >= 100:
        break
s.close()
