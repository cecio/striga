; Test fixture for the lifter: exercises each opcode added in
; arithmetic.py / bitwise.py (ADC, ROR, SHLD, SHRD, RCL, RCR).
;
; Build (Developer Command Prompt for VS):
;     ml64 /c /Fo x86_ops.obj x86_ops.asm
;     link /SUBSYSTEM:CONSOLE /ENTRY:test_ops /NODEFAULTLIB ^
;          /OUT:x86_ops.exe x86_ops.obj

.code

test_ops PROC
    ; --- ADC: 64/32/16/8-bit forms ---
    mov     rax, 1
    mov     rcx, 2
    adc     rax, rcx
    adc     eax, 0FFFFFFFFh
    adc     ax, cx
    adc     al, 7Fh

    ; --- ROR: imm and cl forms across widths ---
    ror     rax, 1
    ror     ecx, 17
    mov     cl, 5
    ror     rdx, cl
    ror     ax, 3

    ; --- SHLD: 64/32/16-bit, imm and cl ---
    shld    rax, rcx, 13
    mov     cl, 7
    shld    edx, esi, cl
    shld    ax, dx, 4

    ; --- SHRD: 64/32-bit, imm and cl ---
    shrd    rax, rcx, 11
    mov     cl, 9
    shrd    edx, esi, cl

    ; --- RCL: the 1-form (special encoding) and cl-form ---
    rcl     rax, 1
    rcl     edx, 5
    mov     cl, 3
    rcl     rbx, cl

    ; --- RCR: 1-form and cl-form ---
    rcr     rax, 1
    rcr     ecx, 4
    mov     cl, 2
    rcr     rdx, cl

    xor     eax, eax
    ret
test_ops ENDP

END
