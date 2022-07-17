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

pwndbg에 대한 다양한 기능을 배우고 싶으면 다음 링크를 참조하시지 바랍니다 [here](https://github.com/pwndbg/pwndbg/blob/dev/FEATURES.md).

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




## Control-flow Hijacking 실습