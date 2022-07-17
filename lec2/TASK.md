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

* Task: invoke execve("/bin/sh", 0, 0) and exit(0) by chaining rop-payload
