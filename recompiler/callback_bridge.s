# Original x86 import bridge: guest RDI/RSI -> explicit CPU + native C service.
.text
.globl _callback_host_bridge
_callback_host_bridge:
    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    subq $72, %rsp
    movq %rdi, 56(%rsp)
    movq $0, 0(%rsp)
    movq %rsi, 8(%rsp)
    movq %rbx, 16(%rsp)
    movq %rbp, 24(%rsp)
    movq $0, 32(%rsp)
    movq $0, 40(%rsp)
    movq $0, 48(%rsp)
    movq %rdi, %rsi
    movq %rsp, %rdi
    xorq %rdx, %rdx
    xorq %rcx, %rcx
    callq _host_service
    movq 0(%rsp), %rax
    movq 8(%rsp), %rsi
    movq 56(%rsp), %rdi
    addq $72, %rsp
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    retq
