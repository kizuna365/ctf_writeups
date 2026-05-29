from pwn import *
elf_file = FILENAME = './go2win'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log


HOST = '92.246.89.201'
POST = 10001
#libc = ELF("./libc.so.6")


if len(sys.argv) > 1 and sys.argv[1] == 'r':
  c = remote(HOST, POST)
else:
  #c = process(FILENAME)
  c = gdb.debug(FILENAME,gdbscript='''b main''')



c.interactive()