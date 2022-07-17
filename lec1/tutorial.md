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

### 구동환경

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


### 소스코드



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


## Control-flow Hijacking 실습