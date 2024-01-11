from pwn import *

def get_libc_addr(p):
    libc = ELF('../.glibc/malloc_testbed_glibc/libc.so.6')
    puts_offset = libc.symbols['puts']
    p.recvuntil('@ ')
    puts = int(p.recvline().strip(), 16)
    libc.address = puts - puts_offset

    return libc


def malloc(p, size):
    p.sendafter('>', b'1')
    p.sendafter('size:', size)

def free(p, index):
    p.sendafter('>', b'3')
    p.sendafter('index:', index)

def edit(p, index, data):
    p.sendafter('>', b'5')
    p.sendafter('index:', index)
    p.sendafter('data:', data)