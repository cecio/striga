# LLVM IR glossary / cheat sheet for Striga

Striga is an experimental **lifter**: it disassembles x86-64 instructions and emits equivalent-ish LLVM IR using the `llvm` Python bindings from `llvm-nanobind`.

The goal of this page is not to teach all of LLVM. It explains the LLVM concepts you will actually see in this repository, especially in:

- `src/striga/semantics.py` - the common lifting helpers
- `src/striga/x86/*.py` - instruction semantics written with LLVM builders
- `lift.py` and `binaryshield.py` - module/context setup and CFG discovery
- `tests/binaryshield.ll` - generated LLVM IR output

## Big picture

The generated lifted functions look like this:

```llvm
define internal void @lifted_0x140016000(ptr %memory, ptr %state) {
initialize:
  %rax = getelementptr inbounds nuw %State, ptr %state, i32 0, i32 0
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
}
```

Striga models machine execution with two pointers:

- `%memory`: a byte-addressed emulated address space.
- `%state`: a `%State` struct containing registers, XMM registers, and flags.

Each x86 instruction address usually becomes one LLVM **basic block** named `insn_0x...`. LLVM SSA temporaries like `%0`, `%1`, `%2` are short-lived calculations inside the lifted code; architectural state lives in `%state` and `%memory` through `load`/`store`.

## Core LLVM objects in this project

| Concept | In `llvm-nanobind` | Where used | What it means here |
|---|---|---|---|
| Context | `Context` from `create_context()` | `lift.py`, `binaryshield.py`, `blog.py` | Owns LLVM types/modules. Do not mix `Type`/`Value` objects from different contexts. |
| Module | `Module` | `Semantics(module)`, `module.add_function(...)` | One LLVM IR container. Holds lifted functions, helper declarations, `%State` type. |
| Type | `Type`, `context.types` | `types.i64`, `types.int_n(32)`, `types.struct(...)` | LLVM is strongly typed. Every `Value` has a type. |
| Value | `Value` | Almost everywhere | Constants, function parameters, instruction results, globals, and instructions are all values. |
| Function | `Function` | `Semantics.begin`, `module.add_function` | A callable IR unit. Striga emits `void (ptr, ptr)` lifted functions. |
| Basic block | `BasicBlock` | `append_basic_block`, `get_or_create_block` | A straight-line instruction list with one terminator at the end. |
| Builder | `Builder` | `with block.create_builder() as ir` | The cursor used to append instructions to a block. In Striga it is usually `sem.ir`. |
| Instruction | also a `Value` | `ir.add`, `ir.load`, `ir.br`, etc. | An operation in a basic block. Many instructions produce an SSA result. |
| Terminator | branch/return/unreachable | `br`, `cond_br`, `ret_void`, `unreachable` | The required final instruction in every basic block. |
| Verifier | `module.verify_or_raise()` | after lifting | Checks type correctness, terminators, malformed CFG, etc. |

## Contexts, modules, and lifetime

Typical pattern:

```python
from llvm import create_context

with create_context() as context:
    with context.create_module("lifted") as module:
        ...
```

Important beginner rules:

- A `Context` owns uniqued types such as `i64`, `ptr`, and `%State`.
- A `Module` belongs to exactly one context.
- A `Builder` should be used inside its `with` block.
- Do not keep using objects after their context/module/builder manager exits.

`blog.py` uses `global_context()` for a tiny demo. For real code, `create_context()` is usually safer because lifetime is explicit.

## Types used by Striga

LLVM IR is strongly typed. Common types in this repo:

| LLVM syntax | Python binding | Meaning |
|---|---|---|
| `void` | `types.void` | No return value. |
| `i1` | `types.i1` | Boolean/predicate bit. Used by `icmp`, `select`, `cond_br`. |
| `i8` | `types.i8` | Byte. Striga stores x86 flags as `i8` in `%State`. |
| `i16`, `i32`, `i64` | `types.i16`, `types.i32`, `types.i64` | Fixed-width integers. |
| `i128` | `types.i128` | Used for XMM registers in this project. |
| `ptr` | `types.ptr` | Opaque pointer in LLVM 21. It has no pointee type attached. |
| `%State = type { ... }` | `types.struct("State", ...)` | Struct containing machine state fields. |
| `void (ptr, ptr)` | `types.function(types.void, [types.ptr, types.ptr])` | Type of a lifted function: memory pointer + state pointer. |

Useful helpers from `src/striga/semantics.py`:

- `sem.const64(x)` -> `i64` constant.
- `sem.const_n(x, bits)` -> integer constant of arbitrary bit width.
- `sem.resize_int(value, ty, sign_extend=False)` -> choose `trunc`, `zext`, or `sext`.

### Signedness note

LLVM integer types are not signed or unsigned. `i32` is just 32 bits. Signedness is chosen by the operation:

- `icmp IntPredicate.ULT` = unsigned less-than.
- `icmp IntPredicate.SLT` = signed less-than.
- `udiv` / `urem` = unsigned division/remainder.
- `sdiv` / `srem` = signed division/remainder.
- `lshr` = logical right shift.
- `ashr` = arithmetic right shift.

This is why x86 flag code carefully chooses predicates such as `ULT`, `EQ`, `NE`, and `SLT`.

## Values and SSA

LLVM IR is in **SSA form**: most computed values are assigned once.

```llvm
%1 = load i64, ptr %rsp
%2 = sub i64 %1, 8
store i64 %2, ptr %rsp
```

- `%1` and `%2` are SSA temporaries.
- `%rsp` is a pointer to the RSP field in `%State`, not the current RSP value.
- `load` reads a value from a pointer.
- `store` writes a value to a pointer.

Striga avoids needing lots of LLVM `phi` nodes by keeping architectural registers in memory (`%state`). At CFG joins, later blocks can simply `load` the current register field. A more optimized lifter might scalarize registers and then need `phi` nodes.

## Functions and helper declarations

Striga creates one lifted function per start address:

```python
fn = module.add_function(f"lifted_{hex(address)}", sem.lifted_ty)
fn.linkage = Linkage.Internal
```

`Linkage.Internal` means the function is private to this module, like a C `static` function.

Striga also declares helper functions without bodies:

```llvm
declare void @__striga_jmp(i64)
declare void @__striga_call(i64)
declare void @__striga_ret(i64)
declare i1 @__striga_undef_cf(i64)
```

A `declare` is an external function prototype. Striga uses these as escape hatches for behavior it does not fully inline into IR:

- dynamic indirect jumps
- calls/returns/syscalls
- x86 flags whose value is architecturally undefined

Do not confuse Striga's `__striga_undef_cf(...)` helpers with LLVM `undef`/`poison`; Striga intentionally emits calls so undefined x86 flag behavior can be controlled or observed by a consumer.

## Basic blocks and CFG

A **basic block** is a label plus a straight-line list of instructions ending in a terminator:

```llvm
insn_0x140016000:
  ...
  br label %insn_0x140016002
```

In Striga:

- `initialize` is the entry block. It creates pointers to fields in `%State` and branches to the first instruction block.
- `insn_0x...` blocks correspond to x86 instruction addresses.
- Linear x86 fallthrough emits `br label %next_block`.
- Conditional jumps emit `cond_br(cond, true_block, false_block)`.
- Dynamic jumps call `__striga_jmp(dst)` and then `ret void`.

LLVM requires every block to end with exactly one terminator. `Semantics.get_or_create_block()` creates placeholder blocks containing `unreachable`; when the real instruction is lifted, Striga erases that placeholder and fills the block.

## Builder: the IR instruction factory

In the Python bindings, a `Builder` has an insertion point and creates instructions there:

```python
with block.create_builder() as ir:
    value = ir.add(lhs, rhs)
    ir.br(next_block)
```

In instruction semantics, `sem.ir` is the current builder. Examples:

| Python | LLVM-ish result | Meaning |
|---|---|---|
| `ir.add(a, b)` | `%x = add i64 %a, %b` | Integer addition. |
| `ir.sub(a, b)` | `%x = sub ...` | Integer subtraction. |
| `ir.and_(a, b)` | `%x = and ...` | Bitwise AND. Underscore avoids Python keyword. |
| `ir.icmp(IntPredicate.EQ, a, b)` | `%x = icmp eq ...` | Integer comparison, returns `i1`. |
| `ir.select(c, a, b)` | `%x = select i1 %c, ...` | Branchless conditional value. |
| `ir.load(ty, ptr)` | `%x = load ty, ptr %p` | Read from memory. |
| `ir.store(value, ptr)` | `store ty %v, ptr %p` | Write to memory. |
| `ir.gep(elem_ty, ptr, [idx])` | `getelementptr elem_ty, ptr %p, ...` | Pointer arithmetic. |
| `ir.br(block)` | `br label %block` | Unconditional branch. |
| `ir.cond_br(c, t, f)` | `br i1 %c, label %t, label %f` | Conditional branch. |
| `ir.ret_void()` | `ret void` | Return from lifted function. |
| `ir.unreachable()` | `unreachable` | Assert control cannot continue. |

## GEP: `getelementptr` without fear

`getelementptr` (GEP) computes an address. It does **not** read memory.

Striga uses two common GEP patterns:

### Byte-addressed emulated memory

```python
ptr = ir.gep(types.i8, memory, [addr])
value = ir.load(ty, ptr)
ir.store(value, ptr)
```

LLVM syntax:

```llvm
%ptr = getelementptr i8, ptr %memory, i64 %addr
%value = load i64, ptr %ptr, align 1
```

Because the element type is `i8`, the index is scaled by 1 byte. This matches x86 byte-addressed memory.

### Fields inside `%State`

```python
reg_ptr = ir.struct_gep(self.state_ty, state, self.reg_indices["rax"], "rax")
```

LLVM syntax:

```llvm
%rax = getelementptr inbounds nuw %State, ptr %state, i32 0, i32 0
```

This computes a pointer to a field in the state struct. Later `load`/`store` instructions read/write the actual register value.

LLVM 21 uses **opaque pointers** (`ptr`), so the GEP builder needs the source element type (`i8` or `%State`) as a separate argument.

## Load/store and alignment

`load` and `store` are how Striga models mutable state:

- `reg_read("rax")` loads from the `%State.rax` field.
- `reg_write("rax", value)` stores to the `%State.rax` field.
- `mem_read(addr, ty)` GEPs into `%memory` and loads.
- `mem_write(addr, value)` GEPs into `%memory` and stores.

Striga sets `align 1` for x86 memory operations because x86 allows unaligned accesses:

```python
load = ir.load(ty, ptr)
load.set_inst_alignment(1)
```

Register-state loads/stores use LLVM's default printed alignment unless explicitly changed.

## Casts and integer resizing

LLVM does not implicitly resize integers. `i8`, `i32`, and `i64` are different types.

Common casts in Striga:

| Cast | Meaning | Example use |
|---|---|---|
| `trunc(value, i8)` | Keep low bits, shrink width. | Reading `al` from `rax`. |
| `zext(value, i64)` | Zero-extend to larger width. | x86 32-bit register writes zero upper bits. |
| `sext(value, i64)` | Sign-extend to larger width. | `movsx`, signed multiply operands. |

`Semantics.resize_int` centralizes this:

```python
src = sem.resize_int(sem.op_read(1), dst.type, sign_extend=True)
```

## Predicates, flags, and booleans

LLVM comparisons return `i1`:

```python
is_zero = sem.ir.icmp(IntPredicate.EQ, result, result.type.constant(0))
```

Striga stores x86 flags as `i8` fields in `%State`, but uses `i1` for calculations:

- `flag_read("zf")` loads an `i8` and compares it with zero, returning `i1`.
- `flag_write("zf", value)` accepts `i1` or `i8` and stores `i8`.
- `flag_write_if(cond, name, value)` uses `select` to update a flag only when needed.

Condition-code logic in `src/striga/x86/control.py` builds x86 predicates from flags, for example:

```python
# ja / nbe: !CF && !ZF
return sem.ir.and_(bool_not(sem, cf), bool_not(sem, zf))
```

## `select` vs branch

`select` chooses a value; it does not change control flow:

```llvm
%x = select i1 %cond, i64 %new, i64 %old
```

Striga uses `select` for things like conditional moves (`cmovcc`) and conditional flag updates. It uses `cond_br` for actual jumps.

## Shifts, poison, and `unreachable`

LLVM has stricter undefined/poison semantics than x86. One important example:

- In LLVM, shifting by a count greater than or equal to the bit width can produce poison.
- In x86, shift counts are masked.

That is why `src/striga/x86/bitwise.py` masks counts and has extra guards for narrow operands before emitting `shl`, `lshr`, or `ashr`.

`unreachable` is also strong: it tells LLVM control flow cannot get there. Striga uses it only as a temporary placeholder in blocks that will be filled later.

## Opcode enum

`Opcode` is used in two ways:

1. Build generic binary operations:

   ```python
   result = sem.ir.binop(Opcode.Add, dst, src)
   ```

2. Inspect existing instructions:

   ```python
   if block.first_instruction.opcode == Opcode.Unreachable:
       block.first_instruction.erase_from_parent()
   ```

You will see opcodes such as `Opcode.Add`, `Opcode.Sub`, `Opcode.And`, `Opcode.Xor`, `Opcode.GetElementPtr`, and `Opcode.Unreachable`.

## Reading generated IR syntax

| Syntax | Meaning |
|---|---|
| `; comment` | LLVM IR comment. |
| `@name` | Global name: function or global variable. |
| `%name` | Local SSA value, parameter, type name, or basic block label depending on context. |
| `declare void @f(i64)` | Function prototype with no body. |
| `define internal void @f(ptr %memory, ptr %state) { ... }` | Function definition. |
| `%State = type { i64, ... }` | Named struct type. |
| `label %insn_...` | Branch target block. |
| `align 1` | Alignment assumption on memory operation. |
| `inbounds` / `nuw` on GEP | Extra no-overflow/in-bounds facts attached by LLVM/bindings. |

## How an x86 instruction semantic usually works

Most semantic functions in `src/striga/x86/*.py` follow this pattern:

1. Read operands using `sem.op_read(index)`.
2. Resize operands to matching LLVM types if needed.
3. Emit LLVM instructions with `sem.ir`.
4. Write the destination with `sem.op_write(index, value)`.
5. Update flags if the x86 instruction defines them.
6. Return successors only if the instruction controls CFG; otherwise return `None` for linear fallthrough.

Example: simplified `add dst, src`:

```python
dst = sem.op_read(0)
src = sem.resize_int(sem.op_read(1), dst.type)
result = sem.ir.add(dst, src)
sem.op_write(0, result)
write_add_flags(sem, dst, src, result)
# return None -> Semantics.lift_bytes emits a fallthrough branch
```

Control-flow instructions return explicit successors:

```python
sem.ir.cond_br(cond, true_block, false_block)
return [Successor(src, sem.const64(true_addr)), Successor(src, sem.const64(false_addr))]
```

`lift.py` uses those `Successor` objects as a worklist to discover more instruction blocks. Constant branch destinations are lifted; non-constant destinations are currently reported/skipped.

## Common pitfalls for beginners

- **Every block needs a terminator.** If you forget `br`, `cond_br`, `ret_void`, or `unreachable`, verification fails.
- **Types must match exactly.** Use `trunc`, `zext`, or `sext`; LLVM will not auto-cast `i8` to `i64`.
- **`i1` is the condition type.** `cond_br` and `select` conditions should be `i1`, not `i8`.
- **GEP is not a load.** GEP computes a pointer; use `load`/`store` to access memory.
- **LLVM integers are bitvectors.** Signedness is in the operation/predicate, not the type.
- **A `store` changes memory, not SSA values.** The next read must `load` again.
- **`select` does not branch.** It computes one value from two alternatives.
- **Avoid LLVM poison.** Shifts and no-wrap flags can introduce poison if their preconditions are false.
- **Run the verifier often.** Striga calls `module.verify_or_raise()` after lifting instructions to catch malformed IR early.

## Quick map from Striga helper to LLVM concept

| Striga helper | LLVM concept emitted/used |
|---|---|
| `begin(address)` | Create/find `Function`, entry `BasicBlock`, initial branch. |
| `get_or_create_block(address)` | Address-to-basic-block CFG node, initially `unreachable`. |
| `reg_read(name)` | `load` from `%State` field; may `trunc` for subregisters. |
| `reg_write(name, value)` | `store` to `%State`; may mask/merge or zero-extend. |
| `mem_read(addr, ty)` | `gep i8` into `%memory`, then `load ty`. |
| `mem_write(addr, value)` | `gep i8` into `%memory`, then `store`. |
| `op_mem(op)` | x86 effective address expression using LLVM arithmetic. |
| `op_read(index)` | Read register/immediate/memory operand as a `Value`. |
| `op_write(index, value)` | Write register or memory operand. |
| `flag_read/write` | Convert between `%State` `i8` flags and LLVM `i1` predicates. |
| `rflags_value()` | Build a packed `i64` RFLAGS value with shifts/ors. |
| `module.verify_or_raise()` | LLVM IR verifier. |

## Suggested reading order in this repo

1. `blog.py` - tiny one-instruction example.
2. `src/striga/semantics.py` - how `%State`, blocks, registers, memory, and operands are modeled.
3. `src/striga/x86/data.py` - simple moves, loads, pushes/pops.
4. `src/striga/x86/arithmetic.py` - arithmetic and flag generation.
5. `src/striga/x86/control.py` - branches, calls, returns, and CFG successors.
6. `tests/binaryshield.ll` - real generated output.
