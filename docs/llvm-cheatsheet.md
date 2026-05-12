# LLVM IR glossary / cheat sheet for Striga

This page explains the LLVM IR vocabulary needed to read Striga output and the Python code that emits it. It assumes the reader knows x86-64 better than LLVM.

Striga lifts x86-64 instructions into LLVM IR with two explicit pieces of machine state:

- `%memory`: a byte-addressed emulated memory region.
- `%state`: a `%State` struct containing registers, XMM registers, `gsbase`, `rip`, and tracked flags.

## Striga IR at a glance

A lifted function usually looks like this:

```llvm
define internal void @lifted_0x140016000(ptr %memory, ptr %state) {
initialize:
  %rip = getelementptr inbounds nuw %State, ptr %state, i32 0, i32 16
  %r15 = getelementptr inbounds nuw %State, ptr %state, i32 0, i32 15
  %rsp = getelementptr inbounds nuw %State, ptr %state, i32 0, i32 6
  br label %insn_0x140016000

insn_0x140016000:
  store i64 5368799232, ptr %rip, align 4
  %0 = load i64, ptr %r15, align 4
  %1 = load i64, ptr %rsp, align 4
  %2 = sub i64 %1, 8
  store i64 %2, ptr %rsp, align 4
  %3 = getelementptr i8, ptr %memory, i64 %2
  store i64 %0, ptr %3, align 1
  br label %insn_0x140016002

insn_0x140016002:
  unreachable
}
```

How to read it:

| IR | Meaning in Striga |
|---|---|
| `define internal void @lifted_0x140016000(...)` | Lifted function for the start address `0x140016000`. |
| `ptr %memory` | Pointer to emulated memory. |
| `ptr %state` | Pointer to the machine-state struct. |
| `initialize:` | Entry block. Striga creates pointers to state fields here. |
| `%rip = getelementptr ...` | Compute the address of the `rip` field inside `%State`. |
| `br label %insn_0x140016000` | Jump from the entry block to the first lifted instruction block. |
| `insn_0x140016000:` | Basic block for one x86 instruction address. |
| `store i64 5368799232, ptr %rip` | Write the current instruction address to `rip`. |
| `%0 = load i64, ptr %r15` | Read architectural `r15`. |
| `%2 = sub i64 %1, 8` | Compute `rsp - 8`. |
| `store i64 %2, ptr %rsp` | Write architectural `rsp`. |
| `%3 = getelementptr i8, ptr %memory, i64 %2` | Compute emulated memory address `%memory + %2`. |
| `store i64 %0, ptr %3, align 1` | Store the pushed value to emulated memory. |
| `unreachable` | Placeholder for a block that has not been filled yet, or a path LLVM may treat as impossible. |

## Glossary

| Term | Meaning | Striga example |
|---|---|---|
| LLVM IR | Low-level typed intermediate representation used by LLVM. | The `.ll` text printed by `str(module)`. |
| Context | Owner for LLVM types, constants, and modules. | `with create_context() as context:` |
| Module | Top-level IR container. | Holds `%State`, lifted functions, and helper declarations. |
| Type | Static type of a value. | `i64`, `i1`, `ptr`, `%State`. |
| Value | Anything usable as an operand. | Constants, parameters, functions, instruction results. |
| Constant | Value known at IR construction time. | `i64 5368799232`, `sem.const64(address)`. |
| Function | Callable IR unit. | `@lifted_0x...`, `@__striga_jmp`. |
| Parameter | Function input value. | `%memory`, `%state`. |
| Basic block | Label plus straight-line instructions ending in a terminator. | `initialize`, `insn_0x140016000`. |
| Instruction | Operation inside a basic block. | `load`, `store`, `sub`, `br`. |
| Terminator | Final instruction of a basic block. | `br`, `cond_br`, `ret void`, `unreachable`. |
| SSA value | Named result with exactly one definition. | `%0`, `%1`, `%2`. |
| CFG | Control-flow graph of basic blocks. | Branches between `insn_0x...` blocks. |
| GEP | `getelementptr`, LLVM pointer arithmetic. | Computes `%memory + address` or a `%State` field pointer. |
| Opaque pointer | LLVM pointer type with no pointee type attached. | `ptr` in LLVM 21. |
| Predicate | Boolean comparison result. | `icmp eq ...` returns `i1`. |
| `select` | Conditional value instruction. | Used for `cmovcc` and conditional flag updates. |
| `phi` | Value chosen from predecessor blocks. | Rare in Striga output because registers live in `%state`. |
| Linkage | Visibility of a global/function. | `internal` makes lifted functions private to the module. |
| Declaration | Function prototype with no body. | `declare void @__striga_jmp(i64)`. |
| Definition | Function with a body. | `define internal void @lifted_... { ... }`. |
| Verifier | LLVM structural checker. | `module.verify_or_raise()`. |
| Builder | Python object that appends IR instructions. | `with block.create_builder() as ir:` and `sem.ir`. |

## Reading LLVM syntax

| Syntax | Meaning |
|---|---|
| `; comment` | Comment. |
| `@name` | Global symbol: function or global variable. |
| `%name` | Local value, basic block label, or named type depending on context. |
| `%0`, `%1` | Auto-numbered SSA values. |
| `i64 8` | Typed integer literal. |
| `ptr %state` | Pointer-typed value. |
| `label %target` | Basic block target. |
| `declare ... @f(...)` | External function prototype. |
| `define ... @f(...) { ... }` | Function body. |
| `%State = type { ... }` | Named struct type. |
| `align 1` | Alignment assumption on a load/store. |
| `inbounds`, `nuw` | LLVM semantic attributes printed on some GEPs. |

## Types used by Striga

LLVM IR is strongly typed. Operand types must match exactly for most instructions.

| LLVM type | Binding | Use in Striga |
|---|---|---|
| `void` | `types.void` | Function returns with no value. |
| `i1` | `types.i1` | Booleans: comparisons, branch conditions, `select` conditions. |
| `i8` | `types.i8` | Bytes and stored flag fields. |
| `i16` | `types.i16` | 16-bit operands. |
| `i32` | `types.i32` | 32-bit operands. |
| `i64` | `types.i64` | 64-bit GPRs and addresses. |
| `i128` | `types.i128` | XMM register storage. |
| `ptr` | `types.ptr` | LLVM 21 opaque pointer. |
| `%State` | `types.struct("State", ...)` | Machine-state struct. |
| `void (ptr, ptr)` | `types.function(types.void, [types.ptr, types.ptr])` | Lifted function type. |

Common integer casts:

| Cast | Meaning | Striga use |
|---|---|---|
| `trunc` | Keep low bits while shrinking width. | Reading `al` from `rax`. |
| `zext` | Zero-extend to a wider integer. | Writing `eax` clears the high half of `rax`. |
| `sext` | Sign-extend to a wider integer. | `movsx`, `movsxd`, signed multiply operands. |

LLVM integer signedness is part of the operation:

| Unsigned operation | Signed operation |
|---|---|
| `icmp ult` | `icmp slt` |
| `icmp ugt` | `icmp sgt` |
| `udiv` / `urem` | `sdiv` / `srem` |
| `lshr` | `ashr` |

## SSA and state

LLVM local values are in SSA form: each SSA name has exactly one definition.

```llvm
%1 = load i64, ptr %rsp
%2 = sub i64 %1, 8
store i64 %2, ptr %rsp
```

`%1` and `%2` are immutable SSA values. The `store` changes the memory location pointed to by `%rsp`; it never changes `%1` or `%2`.

Architectural state in Striga lives in memory-like locations:

- Registers and flags are fields in `%State`.
- x86 memory is under `%memory`.
- Reads use `load`.
- Writes use `store`.

A later block reads the current register value by loading the same `%State` field. This is why Striga output rarely needs `phi` instructions.

## `%State` fields

`%State` is a struct. Striga creates field pointers with `getelementptr` in the `initialize` block.

Current field order:

1. `rax`, `rbx`, `rcx`, `rdx`, `rsi`, `rdi`, `rsp`, `rbp`, `r8` through `r15` as `i64`.
2. `rip` as `i64`.
3. `gsbase` as `i64`.
4. `xmm0` through `xmm31` as `i128`.
5. `cf`, `zf`, `sf`, `of`, `pf`, `af` as `i8`.

Example:

```llvm
%rax = getelementptr inbounds nuw %State, ptr %state, i32 0, i32 0
%rip = getelementptr inbounds nuw %State, ptr %state, i32 0, i32 16
```

`%rax` and `%rip` are pointers to fields. A `load` gets the register value. A `store` writes it.

Flags are stored as `i8` fields because they are part of `%State`. Flag calculations use `i1` predicates. `flag_read()` loads an `i8` and compares it with zero. `flag_write()` converts `i1` back to `i8` when needed.

## GEP: `getelementptr`

GEP computes a pointer. It performs address arithmetic according to an element type.

### Emulated memory

```llvm
%ptr = getelementptr i8, ptr %memory, i64 %addr
%value = load i64, ptr %ptr, align 1
```

The element type is `i8`, so the index is scaled by one byte. This matches x86 byte-addressed memory.

Striga sets `align 1` for emulated x86 memory operations because x86 permits unaligned memory access.

### `%State` fields

```llvm
%rsp = getelementptr inbounds nuw %State, ptr %state, i32 0, i32 6
%old = load i64, ptr %rsp, align 4
```

The first index steps into the struct object. The second index selects a field. LLVM 21 uses opaque `ptr`, so the GEP includes `%State` as the source element type.

## Loads and stores

| IR | Meaning |
|---|---|
| `%x = load i64, ptr %rax` | Read an `i64` from the address held in `%rax`. |
| `store i64 %x, ptr %rax` | Write `%x` to the address held in `%rax`. |
| `%p = getelementptr i8, ptr %memory, i64 %addr` | Compute an emulated memory pointer. |
| `store i32 %v, ptr %p, align 1` | Write a 32-bit value to emulated memory. |

A pointer value such as `%rax` or `%p` is separate from the memory stored at that address.

## Conditions and branches

LLVM comparisons return `i1`:

```llvm
%is_zero = icmp eq i64 %result, 0
```

`cond_br` uses an `i1` condition and changes control flow:

```llvm
br i1 %cond, label %taken, label %fallthrough
```

`select` uses an `i1` condition and chooses a value inside the current block:

```llvm
%x = select i1 %cond, i64 %new, i64 %old
```

Striga uses:

- `cond_br` for x86 conditional jumps.
- `select` for `cmovcc`, `setcc`, and conditional flag updates.

## Helper declarations

Striga declares helper functions for control-flow events and undefined x86 flags:

```llvm
declare void @__striga_jmp(i64)
declare void @__striga_call(i64)
declare void @__striga_ret(i64)
declare void @__striga_syscall(i64)

declare i1 @__striga_undef_cf(i64)
declare i1 @__striga_undef_pf(i64)
declare i1 @__striga_undef_af(i64)
declare i1 @__striga_undef_zf(i64)
declare i1 @__striga_undef_sf(i64)
declare i1 @__striga_undef_of(i64)
```

A `declare` line gives LLVM the function type. The body is supplied by the consumer, interpreter, runtime, or later analysis.

Undefined x86 flags are represented by calls such as `__striga_undef_cf(address)`. These calls are Striga modeling hooks. LLVM `undef` and `poison` are separate IR concepts.

## Blocks, terminators, and placeholders

Every LLVM basic block ends with one terminator.

Common terminators in Striga output:

| Terminator | Meaning |
|---|---|
| `br label %next` | Unconditional jump to another block. |
| `br i1 %cond, label %t, label %f` | Conditional jump. |
| `ret void` | Return from the lifted function. |
| `unreachable` | Control reaching this point is impossible under the IR semantics. |

Striga creates placeholder blocks with `unreachable` before it lifts the corresponding x86 instruction. Generated IR can contain these placeholders when a fallthrough or branch target has been discovered but not emitted yet.

## Builder API cheat sheet

The Python builder is the API that appends LLVM instructions. These calls appear throughout `src/striga/x86/*.py`:

| Python | LLVM instruction |
|---|---|
| `ir.add(a, b)` | `add` |
| `ir.sub(a, b)` | `sub` |
| `ir.mul(a, b)` | `mul` |
| `ir.and_(a, b)` | `and` |
| `ir.or_(a, b)` | `or` |
| `ir.xor(a, b)` | `xor` |
| `ir.icmp(pred, a, b)` | `icmp` |
| `ir.select(c, a, b)` | `select` |
| `ir.load(ty, ptr)` | `load` |
| `ir.store(value, ptr)` | `store` |
| `ir.gep(elem_ty, ptr, indices)` | `getelementptr` |
| `ir.struct_gep(struct_ty, ptr, index, name)` | Struct-field `getelementptr` |
| `ir.trunc(value, ty)` | `trunc` |
| `ir.zext(value, ty)` | `zext` |
| `ir.sext(value, ty)` | `sext` |
| `ir.br(block)` | `br` |
| `ir.cond_br(cond, t, f)` | Conditional `br` |
| `ir.ret_void()` | `ret void` |
| `ir.unreachable()` | `unreachable` |
| `ir.call(fn, args)` | `call` |

`Opcode` is used when a semantic wants a generic binary operation, such as `sem.ir.binop(Opcode.Add, dst, src)`, or when Striga checks whether an existing placeholder instruction is `Opcode.Unreachable`.

## LLVM semantic hazards visible in Striga IR

LLVM has undefined and poison semantics that are stricter than x86 behavior.

| LLVM feature | Why it matters here |
|---|---|
| Shift by count >= bit width | Can produce poison. Striga masks x86 shift counts and guards narrow operands. |
| Division | Division by zero and signed overflow cases have undefined behavior in LLVM. Current `div`/`idiv` IR omits x86 exception behavior. |
| `unreachable` | Lets LLVM assume control never reaches that point. Placeholder use is safe only before later filling or analysis that understands it. |
| `inbounds`, `nuw` | These are semantic promises, not formatting. LLVM can optimize based on them. |
| LLVM `undef` / `poison` | Different from Striga's `__striga_undef_*` helper calls for x86 undefined flags. |

The LLVM verifier checks IR shape and type rules. It does not check that the lifted code matches x86 semantics.

## Quick lookup: Striga names in IR

| Name pattern | Meaning |
|---|---|
| `@lifted_0x...` | Lifted function for a start address. |
| `%memory` | Emulated memory pointer parameter. |
| `%state` | Machine-state pointer parameter. |
| `%rax`, `%rsp`, `%cf` in `initialize` | Pointers to `%State` fields. |
| `%0`, `%1`, `%2` | Temporary SSA values. |
| `insn_0x...` | Basic block for an x86 instruction address. |
| `@__striga_jmp` | Dynamic jump escape hook. |
| `@__striga_call` | Call hook. |
| `@__striga_ret` | Return hook. |
| `@__striga_syscall` | Syscall hook. |
| `@__striga_undef_*` | Hook for an undefined x86 flag value. |
