; nasm -f win64 cfg.asm -o cfg.obj
; lld-link /entry:test_cfg /nodefaultlib cfg.obj /out:cfg.exe /subsystem:console

bits 64
default rel

section .text

global test_cfg

;         ┌──────────────┐
;         │  entry:      │
;         │  cmp rax, 0  │
;         │  je else     │──────┐
;         └──────┬───────┘      │
;           (fallthrough)       │
;         ┌──────▼───────┐ ┌───▼──────────┐
;         │  if_true:    │ │  else:        │
;         │  add rax, 1  │ │  add rax, 2   │
;         │  jmp merge   │ └───┬──────────┘
;         └──────┬───────┘     │(fallthrough)
;                │             │
;         ┌──────▼─────────────▼─┐
;         │  merge:              │  ← diamond merge
;         │  sub rax, 1          │
;         │  jne merge           │  ← back-edge (loop)
;         └──────┬───────────────┘
;                │
;         ┌──────▼───────┐
;         │  exit:       │
;         │  ret         │
;         └──────────────┘
test_cfg:
    cmp rax, 0
    je  .else_block
.if_true:
    add rax, 1
    jmp .merge
.else_block:
    add rax, 2
.merge:
    sub rax, 1
    jne .merge
.exit:
    ret
