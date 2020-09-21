# nothing to say

The following code is vulnerable to a format string exploit:

```
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
