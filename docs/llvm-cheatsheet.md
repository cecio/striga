# LLVM IR cheat sheet for Striga

Use this page when reading or changing the lifter. It covers the LLVM IR patterns emitted by this repository, centered on `src/striga/semantics.py` and `src/striga/x86/*.py`.

## Execution model

Striga lifts one x86-64 start address to one internal LLVM function:

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

The two function parameters are the whole machine model:

- `%memory`: flat byte-addressed emulated memory. x86 addresses are offsets from this pointer.
- `%state`: pointer to `%State`, the mutable register/flag struct.

Each lifted instruction usually lives in a block named `insn_0x...`. `Semantics.lift_bytes()` writes `rip` as the address of the instruction being lifted. Fallthrough blocks may start as `unreachable` placeholders until the worklist lifts them.

## `%State` layout

`Semantics.__init__()` builds `%State` from `self.reg_types`. LLVM struct fields are addressed by index; Striga maps names to indices with `self.reg_indices`.

Current field order:

1. `rax`, `rbx`, `rcx`, `rdx`, `rsi`, `rdi`, `rsp`, `rbp`, `r8` through `r15` as `i64`.
2. `rip` as `i64`.
3. `gsbase` as `i64`.
4. `xmm0` through `xmm31` as `i128`.
5. `cf`, `zf`, `sf`, `of`, `pf`, `af` as `i8`.

Register-pointer GEPs are inserted lazily in `initialize`, immediately before its branch terminator.

Subregister behavior is encoded in `reg_read()` and `reg_write()`:

- `eax`, `ax`, `al`, and similar low subregisters use truncation and masking.
- `ah`, `bh`, `ch`, and `dh` use an 8-bit shift offset.
- 32-bit GPR writes zero-extend into the enclosing 64-bit register.
- Narrow writes merge the changed bits with the old full register value.

## SSA and mutable state

LLVM IR uses SSA for local register values: every local SSA name has exactly one definition.

```llvm
%1 = load i64, ptr %rsp
%2 = sub i64 %1, 8
store i64 %2, ptr %rsp
```

Here `%rsp` names the pointer to the `rsp` field. `%1` is the loaded architectural value. `%2` is the new value. The `store` updates `%State`; it leaves `%1` and `%2` unchanged.

Striga keeps architectural registers in `%state`. At a CFG join, the next block can load the current field value. Phi nodes become necessary if the lifter scalarizes registers across basic blocks.

## LLVM object map

| Concept | Binding | Use in Striga |
|---|---|---|
| Context | `create_context()` | Owns types and modules. Objects from different contexts are incompatible. |
| Module | `context.create_module(...)` | Holds lifted functions, helper declarations, and `%State`. |
| Type | `context.types` | Provides `i64`, `ptr`, `int_n(bits)`, `struct(...)`, `function(...)`. |
| Value | `Value` | Constants, parameters, instruction results, globals, and functions. |
| Function | `module.add_function(...)` | Lifted functions and helper declarations. |
| Basic block | `append_basic_block(...)` | Labelled instruction sequence ending in a terminator. |
| Builder | `block.create_builder()` | Insertion cursor for instructions. Current semantics use `sem.ir`. |
| Verifier | `module.verify_or_raise()` | Checks IR structure after lifting. |

Use LLVM objects only while their context/module managers are alive.

## Types, casts, and signedness

Common types:

| LLVM | Binding | Use |
|---|---|---|
| `void` | `types.void` | No return value. |
| `i1` | `types.i1` | Conditions, comparisons, `select`. |
| `i8` | `types.i8` | Bytes and stored flags. |
| `i16`, `i32`, `i64` | `types.i16`, `types.i32`, `types.i64` | Integer registers and operands. |
| `i128` | `types.i128` | XMM storage as a bit-vector. |
| `ptr` | `types.ptr` | LLVM 21 opaque pointer. |
| `%State` | `types.struct("State", ...)` | Machine-state struct. |
| `void (ptr, ptr)` | `types.function(types.void, [types.ptr, types.ptr])` | Lifted function type. |

LLVM requires explicit integer resizing. `Semantics.resize_int(value, ty, sign_extend=False)` emits:

- `trunc` when the source is wider.
- `zext` when the source is narrower and `sign_extend=False`.
- `sext` when the source is narrower and `sign_extend=True`.

Integer types have no signedness tag. Signedness comes from the operation:

- Unsigned: `icmp ULT`, `icmp UGT`, `udiv`, `urem`, `lshr`.
- Signed: `icmp SLT`, `icmp SGT`, `sdiv`, `srem`, `ashr`.

`op_read()` creates immediates with the operand size reported by Capstone. Instruction handlers choose zero-extension or sign-extension when resizing those immediates.

## Memory and GEP

`getelementptr` computes an address. Loads and stores access memory.

Emulated memory uses byte indexing:

```python
ptr = sem.ir.gep(sem.types.i8, memory, [addr])
load = sem.ir.load(ty, ptr)
load.set_inst_alignment(1)
```

Generated IR:

```llvm
%ptr = getelementptr i8, ptr %memory, i64 %addr
%value = load i64, ptr %ptr, align 1
```

The `i8` element type makes the index scale by one byte. Striga sets `align 1` for x86 memory operations because x86 permits unaligned memory access.

State fields use `struct_gep`:

```python
reg_ptr = ir.struct_gep(self.state_ty, state, self.reg_indices["rax"], "rax")
```

Generated IR:

```llvm
%rax = getelementptr inbounds nuw %State, ptr %state, i32 0, i32 0
```

LLVM 21 opaque pointers store no pointee type, so GEP receives the source element type (`i8` or `%State`) as an explicit argument.

`op_mem()` computes x86 effective addresses:

- base + index * scale + displacement
- RIP-relative addressing with `next_ip = insn.address + insn.size`
- address-size truncation/extension through `self.insn.addr_size`
- GS-relative addressing by adding `gsbase`

## CFG construction

`Semantics.begin(address)` creates or reuses `lifted_<hex(address)>`, creates `initialize`, and branches to the first instruction block.

`get_or_create_block(address)` creates `insn_<hex(address)>` with an `unreachable` placeholder. `lift_bytes()` removes the placeholder before emitting the instruction. If a block already has a non-placeholder first instruction, `lift_bytes()` returns an empty successor list.

Handler return convention:

- Return `None` after straight-line semantics. `lift_bytes()` adds a fallthrough branch.
- Emit a terminator and return `list[Successor]` for control-flow instructions.

`lift.lift()` uses `Successor(src, dst)` as a worklist item. Constant destinations inside the PE image are lifted. Non-constant destinations are reported in verbose mode and skipped by the worklist.

## Helper declarations

`Semantics.__init__()` declares helper functions for escapes and undefined x86 flags:

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

Current control-flow contracts:

- Dynamic `jmp`: call `__striga_jmp(dst)`, then `ret void`.
- `call`: push fallthrough, call `__striga_call(dst)`, branch to fallthrough.
- `ret`: pop destination, adjust `rsp` for `ret imm`, call `__striga_ret(dst)`, then `ret void`.
- `syscall`: save fallthrough to `rcx`, save packed flags to `r11`, mark tracked flags undefined, call `__striga_syscall(insn.address)`, branch to fallthrough.

Undefined x86 flags are modeled with helper calls so an executor or analysis can define their behavior. LLVM `undef` and `poison` are separate IR concepts.

## Flags

Tracked flags are stored as `i8` fields and computed as `i1` predicates.

| Helper | Behavior |
|---|---|
| `flag_read(name)` | Load stored `i8`, compare against zero, return `i1`. |
| `flag_write(name, value)` | Accept `i1` or `i8`, store `i8`. |
| `flag_write_if(cond, name, value)` | Preserve old flag unless `cond` is true. |
| `flag_undef(name)` | Call `__striga_undef_<name>(insn.address)`, return `i1`. |
| `rflags_value()` | Pack tracked flags into `i64`; set reserved bit 1. |

Condition-code logic in `src/striga/x86/control.py` combines these predicates. Example for `ja` / `nbe`:

```python
return sem.ir.and_(bool_not(sem, cf), bool_not(sem, zf))
```

## Common builder operations

`sem.ir` is the current builder. Frequent calls:

- Arithmetic/bitwise: `add`, `sub`, `mul`, `and_`, `or_`, `xor`, `not_`.
- Comparisons and values: `icmp`, `select`.
- Memory/addressing: `load`, `store`, `gep`, `struct_gep`.
- Casts: `trunc`, `zext`, `sext`.
- Shifts/division: `shl`, `lshr`, `ashr`, `udiv`, `urem`, `sdiv`, `srem`.
- Control flow: `br`, `cond_br`, `ret_void`, `unreachable`, `call`.
- Generic binary op dispatch: `binop(Opcode.Add, lhs, rhs)` and similar.

`Opcode` is also used to inspect existing instructions, such as detecting placeholder `Opcode.Unreachable` blocks.

## LLVM semantic hazards

LLVM IR has stricter undefined/poison rules than x86 machine execution:

- Shift counts greater than or equal to the bit width can produce poison. `src/striga/x86/bitwise.py` masks x86 counts and adds guards for narrow operands.
- LLVM division has undefined behavior for division by zero and signed overflow cases. Current `div` and `idiv` handlers emit LLVM division directly, so x86 exception behavior is omitted.
- `unreachable` asserts impossible control flow. Striga uses it for placeholders and for helper-terminated paths.
- No-wrap flags and `inbounds` facts strengthen IR semantics. GEP attributes printed by the binding should be treated as semantic facts, not decoration.
- The verifier checks malformed IR; it does not prove x86 semantic correctness.

Modeling limitations visible in current code:

- `lock` prefixes preserve single-threaded instruction results; inter-thread atomicity is not modeled.
- Dynamic branch destinations are helper calls plus worklist skips.
- SIMD support is a small set of bit-vector moves/logical operations over `i128`.
- `popfq` restores only the tracked flag fields.

## Instruction semantic pattern

Straight-line instruction handlers usually follow this shape:

```python
dst = sem.op_read(0)
src = sem.resize_int(sem.op_read(1), dst.type)
result = sem.ir.add(dst, src)
sem.op_write(0, result)
write_add_flags(sem, dst, src, result)
# Return None: lift_bytes() emits the fallthrough branch.
```

Control-flow handlers emit their own terminator and return successors:

```python
sem.ir.cond_br(cond, true_block, false_block)
return [
    Successor(src, sem.const64(true_addr)),
    Successor(src, sem.const64(false_addr)),
]
```

## Editing checklist

- Every block needs one terminator.
- `cond_br` and `select` conditions must be `i1`.
- Integer widths must match before arithmetic, comparisons, stores, and calls.
- Use signed predicates/ops only when the x86 instruction requires signed semantics.
- Use `align 1` for x86 memory loads/stores.
- Mask or guard shift counts before emitting LLVM shifts.
- Preserve x86 subregister semantics, especially 32-bit zero-extension and high-8 registers.
- Run `module.verify_or_raise()` after new emission paths.
