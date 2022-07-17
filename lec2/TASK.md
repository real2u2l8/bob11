LEC2
====

* checksec

```sh
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

* gadget information (ex1 binary)

```sh
Gadgets information
============================================================
0x08049483 : pop ebp ; ret
0x08049480 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x08049022 : pop ebx ; ret
0x08049482 : pop edi ; pop ebp ; ret
0x08049481 : pop esi ; pop edi ; pop ebp ; ret
0x0804900e : ret
0x0804924b : ret 0xe8c1
0x0804906a : ret 0xffff
```

* Task: invoke execve("/bin/sh", 0, 0) and exit(0) by chaining rop-payload
