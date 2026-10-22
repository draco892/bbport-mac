# Original x86 oracle bridge. The synthetic functions cannot access r12-r15.
# C arguments: function, region, scalar, output CPU snapshot.
.text
.globl _stack_original_call
_stack_original_call:
    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    subq $8, %rsp
    movq %rcx, %r12
    movq %rdi, %r13
    movq %rsp, %r14
    movq %rsi, %rdi
    movq %rdx, %rsi
    movabsq $0x1122334455667788, %rbx
    movabsq $0x8877665544332211, %rbp
    xorl %eax, %eax
    callq *%r13
    movq %rax, 0(%r12)
    movq %rsi, 8(%r12)
    movq %rbx, 16(%r12)
    movq %rbp, 24(%r12)
    movq %rsp, %r10
    subq %r14, %r10
    movq %r10, 32(%r12)
    addq $8, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    retq
