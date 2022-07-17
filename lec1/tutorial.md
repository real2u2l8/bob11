Lec1 Tutorial
==============

## pwndbg를 활용한 바이너리 실행

pwndbg를 설치하면 gdb wrapper가 여러분의 홈디렉토리에 생성됩니다. (~/.gdbinit 파일을 체크해보세요). wrapper를 통해 기존 gdb 명령어를 실행할 수 있고, 새롭게 편리한 명령들을 실행할수도 있습니다. 디버거를 구동시키는 방법은 아래와 같습니다.

```sh
$ gdb [binary name]
```

구동시키면 아래와 같은 화면이 나올 겁니다. 단순히 `r` 또는 `run` 명령으로 프로세스를 실행시킬 수 있습니다.

<img src="img/pic1.png" alt="pwndbg_start" width="600" class="center">

디버깅, 특히 pwndbg wrapper의 장점은 context를 보여주는 방식입니다. 아래의 그립을 보면 매 instruction마다 한페이지에 가까운 정보를 보여주는 것을 알 수 있습니다.

* register들
* instruction
* 소스코드 (심볼이 있는 경우)
* stack

<img src="img/pic2.png" alt="pwndbg_context" width="600" class="center">

pwndbg에 대한 다양한 기능을 배우고 싶으면 다음 링크를 참조하시지 바랍니다 [(여기)](https://github.com/pwndbg/pwndbg/blob/dev/FEATURES.md).

관심이 있다면 아래의 기능을 스스로 사용해보시기 바랍니다.

| Command       | Description                                               |
|---------------|-----------------------------------------------------------|
|`aslr`         | Inspect or modify ASLR status                             |
|`checksec`     | Prints out the binary security settings using `checksec`. |
|`elfheader`    | Prints the section mappings contained in the ELF header.  |
|`hexdump`      | Hexdumps data at the specified address (or at `$sp`).     |
|`main`         | GDBINIT compatibility alias for `main` command.           |
|`nearpc`       | Disassemble near a specified address.                     |
|`nextcall`     | Breaks at the next call instruction.                      |
|`nextjmp`      | Breaks at the next jump instruction.                      |
|`nextjump`     | Breaks at the next jump instruction.                      |
|`nextret`      | Breaks at next return-like instruction.                   |
|`nextsc`       | Breaks at the next syscall not taking branches.           |
|`nextsyscall`  | Breaks at the next syscall not taking branches.           |
|`pdisass`      | Compatibility layer for PEDA's pdisass command.           |
|`procinfo`     | Display information about the running process.            |
|`regs`         | Print out all registers and enhance the information.      |
|`stack`        | Print dereferences on stack data.                         |
|`search`       | Search memory for bytes, strings, pointers, and integers. |
|`telescope`    | Recursively dereferences pointers.                        |
|`vmmap`        | Print virtual memory map pages.                           |


## 첫 바이너리를 디버깅해보자

### 구동환경 구성

아래의 명령어를 이용하여 파일에 적절한 권한을 부여합시다.

```sh
# add user “lec1”
$ sudo useradd lec1

# generate a flag and grant proper privilege
$ echo "This is my flag" > flag
$ chmod 440 flag
$ sudo chown lec1:lec1 flag

# take care of the binary
$ sudo chown lec1:lec1 ex2
$ sudo chmod 2755 ex2
```

위 명령어를 사용하여 `lec1` 사용자만 flag를 읽을 수 있게 하였습니다. `ls` 명령어를 사용하여 파일의 소유자와 privilege를 확인할 수 있습니다.

```
$ ls -als

total 112
 4 drwxr-xr-x 3 jjung jjung  4096 Jul 18 05:14 .
 4 drwxr-xr-x 5 jjung jjung  4096 Jul 18 04:20 ..
 4 -rw-r--r-- 1 jjung jjung    13 Jul 12 06:37 .gitignore
 4 -rw-r--r-- 1 jjung jjung   189 Jul 12 05:43 Makefile
16 -rwxr-xr-x 1 jjung jjung 16368 Jul 12 05:43 ex1
 4 -rw-r--r-- 1 jjung jjung   310 Jul 12 05:43 ex1.c
20 -rwxr-sr-x 1 lec1  lec1  16620 Jul 12 05:43 ex2
 4 -rw-r--r-- 1 jjung jjung   445 Jul 12 05:43 ex2.c
16 -rwxr-xr-x 1 jjung jjung 16140 Jul 12 05:43 ex3
 4 -rw-r--r-- 1 jjung jjung   169 Jul 12 05:43 ex3.c
20 -rwxr-xr-x 1 jjung jjung 16804 Jul 12 05:43 ex4
 4 -r--r----- 1 lec1  lec1     16 Jul 18 05:13 flag
 4 drwxr-xr-x 2 jjung jjung  4096 Jul 18 04:54 img
 4 -rw-r--r-- 1 jjung jjung  4043 Jul 18 05:13 tutorial.md
```

flag파일의 경우 소유자는 `lec1`이며 runtime 실행모드는 `-r--r-----` 입니다.

* 첫번째 `-`: 디렉토리 여부
* 두번째 `r--`: 파일의 소유자는 해당 파일을 읽을 수 있음
* 세번째 `r--`: 해당 그룹에 속하는 user는 파일을 읽을 수 있음
* 네번째 `---`: 그 밖에 다른 사람들은 아무것도 할 수 없음

여기서 특이한 것은 ex2 바이너리의 경우 `-rwxr-sr-x`로 표시되어 있습니다. 이것이 가리키는 의미는 아래와 같습니다.

* 파일 소유자: r/w/x를 할 수 있는 권한이 있음
* 그룹멤버: r/x를 할 수 있음, 그리고 해당 파일을 실행하는 동안 그룹멤버의 privilege를 가지게 됨
* 다른 사람들은 r/x의 권한을 가짐


### ex2.c 소스코드


```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void spawn_shell(){
        printf("There you are!\n");
        setregid(getegid(), getegid());
        execl("/bin/bash", "bash", NULL);
}

int main(){
        char buf[512];
        printf("What is your password?\n");
        scanf("%s", buf);
        if(strcmp(buf, "Password") == 0){
                printf("Correct!\n");
                spawn_shell();
        }
        else{
                printf("Wrong password!\n");
        }
        return 0;
}
```

우선 `scanf()` 함수에서 buf로 문자열을 받습니다. `strcmp()` 함수에서 만약 사용자의 입력값이 `Password` 인 경우 `spawn_shell()` 함수를 실행합니다. 또한 호출된 함수에서는 "/bin/sh" 을 실행합니다.

ex2 바이너리의 경우 해당 바이너리를 실행하는 동안 ex2 그룹이 가지는 권한을 얻을 수 있기 때문에 spawn된 쉘에서는 flag를 읽을 수 있습니다.


```sh
$ cat flag
cat: flag: Permission denied

$ ./ex2
What is your password?
Password
Correct!
There you are!

~/bob/bob11-repo/lec1$ cat flag
This is my flag
```

### pwngdb로 instruction 따라가보기

먼저 main함수를 봅시다. `disas` 명령어를 사용하여 disassembled instruction들을 볼 수 있습니다.

```sh
pwndbg> disas main
Dump of assembler code for function main:
   0x08049230 <+0>:     push   ebp
   0x08049231 <+1>:     mov    ebp,esp
   0x08049233 <+3>:     sub    esp,0x218
   0x08049239 <+9>:     mov    DWORD PTR [ebp-0x4],0x0
   0x08049240 <+16>:    lea    eax,ds:0x804a022
   0x08049246 <+22>:    mov    DWORD PTR [esp],eax
   0x08049249 <+25>:    call   0x8049050 <printf@plt>
   0x0804924e <+30>:    lea    ecx,[ebp-0x204]
   0x08049254 <+36>:    lea    edx,ds:0x804a03a
   0x0804925a <+42>:    mov    DWORD PTR [esp],edx
   0x0804925d <+45>:    mov    DWORD PTR [esp+0x4],ecx
   0x08049261 <+49>:    mov    DWORD PTR [ebp-0x208],eax
   0x08049267 <+55>:    call   0x80490a0 <__isoc99_scanf@plt>
   0x0804926c <+60>:    lea    ecx,[ebp-0x204]
   0x08049272 <+66>:    mov    edx,esp
   0x08049274 <+68>:    mov    DWORD PTR [edx],ecx
   0x08049276 <+70>:    mov    DWORD PTR [edx+0x4],0x804a03d
   0x0804927d <+77>:    mov    DWORD PTR [ebp-0x20c],eax
   0x08049283 <+83>:    call   0x8049040 <strcmp@plt>
   0x08049288 <+88>:    cmp    eax,0x0
   0x0804928b <+91>:    jne    0x80492af <main+127>
   0x08049291 <+97>:    lea    eax,ds:0x804a046
   0x08049297 <+103>:   mov    DWORD PTR [esp],eax
   0x0804929a <+106>:   call   0x8049050 <printf@plt>
   0x0804929f <+111>:   mov    DWORD PTR [ebp-0x210],eax
   0x080492a5 <+117>:   call   0x80491d0 <spawn_shell>
   0x080492aa <+122>:   jmp    0x80492bd <main+141>
   0x080492af <+127>:   lea    eax,ds:0x804a050
   0x080492b5 <+133>:   mov    DWORD PTR [esp],eax
   0x080492b8 <+136>:   call   0x8049050 <printf@plt>
   0x080492bd <+141>:   xor    eax,eax
   0x080492bf <+143>:   add    esp,0x218
   0x080492c5 <+149>:   pop    ebp
   0x080492c6 <+150>:   ret
End of assembler dump.
```

특히 main함수의 가장 첫 부분과 마지막 부분은 `function prologue`와 `function epilogue`로 불립니다. function prologue는 현재의 base pointer를 push하며 (`push ebp`) 나중에 함수가 끝날때 epilogue에서 복구합니다. 이후 base pointer는 현재 stack pointer의 주소를 가지게 됩니다. 그래서 base pointer는 스택의 가장 끝을 가리키지요 (`mov ebp, esp`). 그 다음으로 지역변수들이 들어갈 수 있는 공간을 만들어주기 위해 stack pointer 값이 줄어들게 됩니다 (`sub esp, N`). function epilogue에서는 prologue와 정반대되는 일을 합니다.

```sh
   0x08049230 <+0>:     push   ebp
   0x08049231 <+1>:     mov    ebp,esp
   0x08049233 <+3>:     sub    esp,0x218
   ...
   0x080492bf <+143>:   add    esp,0x218
   0x080492c5 <+149>:   pop    ebp
   0x080492c6 <+150>:   ret
```



## Control-flow Hijacking 실습

`ex4` 바이너리를 가지고 control-flow를 hijack 해 봅시다. 우리의 목표는 `impossible_trigger()` 함수를 호출하는 것입니다. 현재 정의된 `global_var` 변수가 있고 초기값은 0이 입력되어 있습니다. 코드내부에 `global_var`를 변경하는 부분이 없기 때문에, 정상적인 실행흐픔에서는 `impossible_trigger()` 함수가 호출될 수 없습니다. 하지만 memory corruption 취약점을 활용해서 `impossible_trigger()` 함수를 호출할 수 있습니다.