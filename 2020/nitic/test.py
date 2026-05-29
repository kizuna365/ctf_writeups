from pwn import *
elf_file = FILENAME = '/home/k1zuna/D/2020/nitic/VillagerZ'
elf = context.binary = ELF(elf_file)


io = gdb.debug([FILENAME], gdbscript='''
b main
continue
''')

io.interactive()