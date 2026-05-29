from pwn import *
elf_file = FILENAME = '/home/k1zuna/D/2020/nitic/VillagerZ'
elf = context.binary = ELF(elf_file)

io = process(FILENAME)
sleep(1)
c = gdb.attach(io, gdbscript="breakrva *vuln+82\n")

io.interactive()