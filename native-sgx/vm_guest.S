/* SPDX-License-Identifier: MIT
 * No OS, BIOS, Windows runtime, devices or system calls. These bounded
 * stubs execute SGX instructions in a private KVM address space.
 */
.text
.code64
.global _start
_start:
    mov $0x60000, %r8
    mov 0(%r8), %rax
    mov 8(%r8), %rbx
    mov 16(%r8), %rcx
    mov 24(%r8), %rdx
    .byte 0x0f, 0x01, 0xcf  /* ENCLS */
    mov %rax, 32(%r8)
    pushfq
    popq 40(%r8)
    cmpq $1, 0(%r8)
    jne report
    cmpq $0, 48(%r8)
    je report
    mov 56(%r8), %rbx
    mov 16(%r8), %r10
    mov $16, %r11
extend:
    mov $6, %eax
    mov %r10, %rcx
    .byte 0x0f, 0x01, 0xcf
    add $256, %r10
    dec %r11
    jnz extend
report:
    mov $0xf1, %dx
    xor %eax, %eax
    out %al, %dx
    hlt

.org 0x100
enter:
    mov $0x60000, %r8
    mov 0(%r8), %rdi
    mov 8(%r8), %rbx
    mov 24(%r8), %rsi
    lea aep(%rip), %rcx
    mov $2, %eax
    .byte 0x0f, 0x01, 0xd7  /* ENCLU[EENTER] */
    mov $0x60000, %r8
    mov %rsi, 32(%r8)
    mov %rdi, 40(%r8)
    mov %rsp, 64(%r8)
    mov %rbp, 72(%r8)
    mov $0xf1, %dx
    xor %eax, %eax
    out %al, %dx
    jmp .

.org 0x200
aep:
    mov $0x60000, %r8
    incq 80(%r8)
    cmpq $1024, 80(%r8)
    ja aep_bound
    lea aep(%rip), %rcx
    mov $3, %eax
    .byte 0x0f, 0x01, 0xd7  /* ENCLU[ERESUME] after host interrupts */
aep_bound:
    movq $1, 48(%r8)
    mov $0xf1, %dx
    xor %eax, %eax
    out %al, %dx
    jmp .

.org 0x300
exception:
    mov $0x60000, %r8
    movq $0x100, 48(%r8)
    mov (%rsp), %rax
    mov %rax, 32(%r8)
    mov $0xf1, %dx
    xor %eax, %eax
    out %al, %dx
    hlt
.section .note.GNU-stack,"",@progbits
