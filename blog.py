from striga import Semantics
from llvm import global_context

with global_context().create_module("blog") as module:
    sem = Semantics(module, verbose=True)
    entry = 0x140001000
    # sem.begin(entry)
    # sem.lift_bytes(entry, b"\x48\x89\xC8") # mov rax, rcx
    # sem.lift_bytes(entry, b"\x48\x8B\x44\x8B\x2A") # mov rax, [rbx+rcx*4+42]
    # sem.lift_bytes(entry, b"\x48\x8b\x43\x2a")  # mov rax, [rbx+42]
    # sem.lift_bytes(entry, b"\x48\x31\xD8") # xor rax, rbx
    sem.lift_bytes(entry, b"\x75\x12")  # je imm
    # sem.lift_bytes(entry, b"\xff\xe3") # jmp rbx
    # sem.lift_bytes(entry, b"\xe8\x00\x00\x10\x00") # call imm
    # sem.lift_bytes(entry, b"\xc3")  # ret
    print(module)
