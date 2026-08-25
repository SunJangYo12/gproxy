/*
(gdb) p a
$1 = {<text variable, no debug info>} 0x401156 <a>
(gdb) p b
$2 = {<text variable, no debug info>} 0x40116b <b>
(gdb) b main
Breakpoint 1 at 0x401180
(gdb) r
Starting program: /home/jin/Lab/gdb_hook/test 

Breakpoint 1, 0x0000000000401180 in main ()

call (int)mprotect((void*)((long)$tramp & ~0xfff), 0x1000, 7)

(gdb) set $a = (long)0x401156
(gdb) set $b = (long)0x40116b
(gdb) set {char} $a = 0x48
(gdb) set {char} ($a+1) = 0xB8
(gdb) set {long} ($a+2) = $b
(gdb) set {char} ($a+10) = 0xFF
(gdb) set {char} ($a+11) = 0xE0
(gdb) c
Continuing.
Function B


=============
RET shellcode

(gdb) set $a = (long)0x401156
(gdb) set $hook = (void*)malloc(0x100)
(gdb) call (int)mprotect((void*)((long)$hook & ~0xfff), 0x1000, 7)
$3 = 0
(gdb) set {char} $hook = 0xC3  # simple shellcode RET
(gdb) set {char} $a = 0x48     # mov
(gdb) set {char} ($a+1) = 0xB8 # rax
(gdb) set {long} ($a+2) = $hook # 8byte address
(gdb) set {char} ($a+10) = 0xFF # jmp
(gdb) set {char} ($a+11) = 0xE0 # rax
(gdb) c



=============
print shellcode
set {char[31]} $hook = {
  0x48,0xc7,0xc0,0x01,0x00,0x00,0x00,      # mov rax,1
  0x48,0xc7,0xc7,0x01,0x00,0x00,0x00,      # mov rdi,1
  0x48,0x8d,0x35,0x0a,0x00,0x00,0x00,      # lea rsi,[rip+0xa]
  0x48,0xc7,0xc2,0x05,0x00,0x00,0x00,      # mov rdx,5
  0x0f,0x05,                                # syscall
  0xc3                                       # ret
}
(gdb) set $a = (long)0x401156
(gdb) set $hook = (void*)malloc(0x100)
(gdb) call (int)mprotect((void*)((long)$hook & ~0xfff), 0x1000, 7)
$6 = 0
(gdb) set {char[31]} $hook = {0x48,0xc7,0xc0,0x01,0x00,0x00,0x00,0x48,0xc7,0xc7,0x01,0x00,0x00,0x00,0x48,0x8d,0x35,0x0a,0x00,0x00,0x00,0x48,0xc7,0xc2,0x05,0x00,0x00,0x00,0x0f,0x05,0xc3 }
(gdb) set {char[6]} ($hook+31) = "HOOK\n"
(gdb) set {char} $a = 0x48
(gdb) set {char} ($a+1) = 0xB8
(gdb) set {long} ($a+2) = $hook
(gdb) set {char} ($a+10) = 0xFF
(gdb) set {char} ($a+11) = 0xE0
(gdb) c
Continuing.
HOOK





==========
trampolin basic (tidak melakukan apa" hanya ret)

(gdb) set $tramp = (void*) malloc(0x100)
(gdb) call (int)mprotect((void*)((long)$tramp & ~0xfff), 0x1000, 7)
(gdb) set {char} $tramp = 0xC3

(gdb) set $hook = (void*) malloc(0x100)
(gdb) call (int)mprotect((void*)((long)$hook & ~0xfff), 0x1000, 7)
(gdb) set {char} $hook = 0x48
(gdb) set {char} ($hook+1) = 0xB8
(gdb) set {long long} ($hook+2) = $tramp
(gdb) set {char} ($hook+10) = 0xFF
(gdb) set {char} ($hook+11) = 0xE0

(gdb) p a
$4 = {<text variable, no debug info>} 0x401156 <a>
(gdb) set $a = (long)0x401156
(gdb) set {char}$a = 0x48
(gdb) set {char} ($a+1) = 0xB8
(gdb) set {long long} ($a+2) = $hook
(gdb) set {char} ($a+10) = 0xFF
(gdb) set {char} ($a+11) = 0xE0
(gdb) c
Continuing.



=============
Tramploin hook print

(gdb) set $tramp = (void*) malloc(0x100)
(gdb) call (int)mprotect((void*)((long)$tramp & ~0xfff), 0x1000, 7)
$1 = 0
(gdb) set {char} $tramp = 0xC3
(gdb) set $hook = (void*) malloc(0x100)
(gdb) call (int)mprotect((void*)((long)$hook & ~0xfff), 0x1000, 7)
$2 = 0
(gdb) set {char[31]} $hook = {0x48,0xc7,0xc0,0x01,0x00,0x00,0x00,0x48,0xc7,0xc7,0x01,0x00,0x00,0x00,0x48,0x8d,0x35,0x0a,0x00,0x00,0x00,0x48,0xc7,0xc2,0x05,0x00,0x00,0x00,0x0f,0x05,0xc3 }
(gdb) set {char} ($hook+31) = 0x48
(gdb) set {char} ($hook+32) = 0xB8
(gdb) set {long long} ($hook+33) = $tramp
(gdb) set {char} ($hook+41) = 0xFF
(gdb) set {char} ($hook+42) = 0xE0
(gdb) set {char[6]} ($hook+43) = "HOOK\n"
(gdb) p a
$3 = {<text variable, no debug info>} 0x401156 <a>
(gdb) set $a = (long)0x401156
(gdb) set {char}$a = 0x48
(gdb) set {char} ($a+1) = 0xB8
(gdb) set {long long} ($a+2) = $hook
(gdb) set {char} ($a+10) = 0xFF
(gdb) set {char} ($a+11) = 0xE0


*/


#include <stdio.h>
#include <unistd.h>

void a() {
    printf("Function A\n");
}

void b() {
    printf("Function B\n");
}


int main() {
    while (1) {
        a();
        sleep(1);
    }
    return 0;
}

