from pwn import *
elf_file = FILENAME = './chall'
elf = context.binary = ELF(elf_file)
context.log_level = 'debug'
_asm = '''
    push rdx
    '''
print((repr(asm(_asm))))