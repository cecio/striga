from queue import Queue
from typing import TypeAlias, Callable, NamedTuple

from pefile import PE

from capstone import (
    CS_ARCH_X86,
    CS_MODE_64,
    CS_OP_REG,
    CS_OP_MEM,
    CS_OP_IMM,
    Cs,
    CsInsn,
)
from capstone.x86 import X86Op
from capstone.x86_const import (
    X86_REG_RIP,
    X86_REG_INVALID,
    X86_REG_GS,
)

from llvm import (
    create_context,
    Value,
    Builder,
    Module,
    Function,
    Linkage,
    Opcode,
    IntPredicate,
    Type,
    BasicBlock,
)


class GPR(NamedTuple):
    r64: str
    r32: str
    r16: str
    r8l: str
    r8h: str = ""


GPRS = [
    GPR("rax", "eax", "ax", "al", "ah"),
    GPR("rbx", "ebx", "bx", "bl", "bh"),
    GPR("rcx", "ecx", "cx", "cl", "ch"),
    GPR("rdx", "edx", "dx", "dl", "dh"),
    GPR("rsi", "esi", "si", "sil"),
    GPR("rdi", "edi", "di", "dil"),
    GPR("rsp", "esp", "sp", "spl"),
    GPR("rbp", "ebp", "bp", "bpl"),
    GPR("r8", "r8d", "r8w", "r8b"),
    GPR("r9", "r9d", "r9w", "r9b"),
    GPR("r10", "r10d", "r10w", "r10b"),
    GPR("r11", "r11d", "r11w", "r11b"),
    GPR("r12", "r12d", "r12w", "r12b"),
    GPR("r13", "r13d", "r13w", "r13b"),
    GPR("r14", "r14d", "r14w", "r14b"),
    GPR("r15", "r15d", "r15w", "r15b"),
]


class Successor(NamedTuple):
    src: int
    dst: Value


SemanticFn: TypeAlias = Callable[["Semantics"], list[Successor] | None]
_semantics: dict[str, SemanticFn] = {}


def semantic(fn: SemanticFn):
    name = getattr(fn, "__name__")
    _semantics[name.removesuffix("_")] = fn
    return fn


class Semantics:
    def __init__(self, module: Module, *, verbose=False):
        self.module = module
        self.verbose = verbose

        # Disassembler
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True

        # Aliases
        self.context = module.context
        types = self.context.types
        self.types = self.context.types
        self.i64 = types.i64

        # Register state
        self.subregs: dict[str, tuple[str, int, int]] = {}
        for r64, r32, r16, r8l, r8h in GPRS:
            self.subregs[r32] = (r64, 32, 0)
            self.subregs[r16] = (r64, 16, 0)
            self.subregs[r8l] = (r64, 8, 0)
            self.subregs[r8h] = (r64, 8, 1)

        self.reg_sizes = {
            **{gpr.r64: 64 for gpr in GPRS},
            "rip": 64,
            "gsbase": 64,
            "cf": 8,
            "zf": 8,
            "sf": 8,
            "of": 8,
            "pf": 8,
            "af": 8,
        }
        self.reg_types = {
            name: types.int_n(size) for name, size in self.reg_sizes.items()
        }
        state_ty = types.get("State")
        if state_ty is None:
            # TODO: update llvm-nanobind to deduplicate by name
            state_ty = types.struct(self.reg_types.values(), name="State")
        self.state_ty = state_ty
        self.lifted_ty = types.function(types.void, [types.ptr, types.ptr])

        # TODO: update llvm-nanobind to add module.get_or_insert_function
        indirect_jmp = module.get_function("indirect_jmp")
        if indirect_jmp is None:
            indirect_jmp = module.add_function(
                "indirect_jmp", types.function(types.void, [types.i64])
            )
        self.indirect_jmp = indirect_jmp

        # Set per function lifting
        self.insn_blocks: dict[int, BasicBlock] = {}
        self.function: Function
        self.reg_ptrs: dict[str, Value] = {}

        # Set per instruction
        self.ir: Builder
        self.insn: CsInsn

    def const64(self, val: int, sign_extend=False):
        return self.const_n(val, 64, sign_extend)

    def const_n(self, val: int, bits: int, sign_extend=False):
        return self.types.int_n(bits).constant(val, sign_extend)

    def begin(self, address: int) -> Function:
        name = f"lifted_{hex(address)}"
        fn = self.module.get_function(name)
        if fn is None:
            fn = self.module.add_function(name, self.lifted_ty)
            fn.linkage = Linkage.Internal
            memory, state = fn.params
            memory.name = "memory"
            state.name = "state"
            self.function = fn

            entry = fn.append_basic_block("initialize")
            assert fn.last_basic_block == entry
            with entry.create_builder() as ir:
                for i, name in enumerate(self.reg_sizes.keys()):
                    reg_ptr = ir.struct_gep(self.state_ty, state, i, name)
                    self.reg_ptrs[name] = reg_ptr
                ir.br(self.get_or_create_block(address))
        else:
            self.function = fn
            self.reg_ptrs = {}
            entry = fn.entry_block
            assert fn.last_basic_block == entry
            assert entry.name == "initialize", (
                "unexpected basic block for lifted function"
            )
            for insn in entry.instructions:
                if (
                    insn.opcode == Opcode.GetElementPtr
                    and insn.gep_source_element_type == self.state_ty
                ):
                    assert insn.name in self.reg_types, "unexpected GEP"
                self.reg_ptrs[insn.name] = insn
        return self.function

    def cs_disasm(self, address: int, code: bytes) -> CsInsn:
        for insn in self.cs.disasm(code, address, count=1):  # ty: ignore[missing-argument, invalid-argument-type]
            return insn
        raise ValueError(f"Failed to disassemble {code.hex()}@{hex(address)}")

    def get_or_create_block(self, address: int) -> BasicBlock:
        block = self.insn_blocks.get(address)
        if block is None:
            block = self.function.append_basic_block(f"insn_{hex(address)}")
            with block.create_builder() as ir:
                ir.unreachable()
            self.insn_blocks[address] = block
        assert block.function == self.function
        return block

    def lift_bytes(self, address: int, code: bytes) -> list[Successor]:
        insn = self.cs_disasm(address, code)
        if self.verbose:
            print(";", hex(insn.address), insn.mnemonic, insn.op_str)

        # Get or create — the block may already exist as a branch target
        block = self.get_or_create_block(address)
        assert block.first_instruction
        if block.first_instruction.opcode == Opcode.Unreachable:
            block.first_instruction.erase_from_parent()

        with block.create_builder() as ir:
            self.ir = ir
            self.insn = insn
            self.reg_write("rip", self.const64(address))
            handler = _semantics.get(insn.mnemonic)
            if not handler:
                raise NotImplementedError(insn.mnemonic)

            successors = handler(self)
            if successors is None:
                # Linear fallthrough — handler didn't emit a terminator
                fallthrough = address + insn.size
                ir.br(self.get_or_create_block(fallthrough))
                successors = [Successor(address, self.const64(fallthrough))]

            self.module.verify_or_raise()
            return successors

    def reg_name(self, reg_id: int) -> str:
        return self.insn.reg_name(reg_id)  # pyright: ignore[reportReturnType]

    def reg_read(self, name: str):
        reg_ptr = self.reg_ptrs.get(name)
        if reg_ptr is None:
            name, size, offset = self.subregs[name]
            assert offset == 0, "r8h not supported"
            reg_ptr = self.reg_ptrs[name]
            reg_ty = self.types.int_n(size)
        else:
            reg_ty = self.reg_types[name]
        return self.ir.load(reg_ty, reg_ptr)

    def reg_write(self, name: str, value: Value):
        reg_ptr = self.reg_ptrs.get(name)
        if reg_ptr is None:
            name, size, offset = self.subregs[name]
            assert offset == 0, "r8h not supported"
            reg_ptr = self.reg_ptrs[name]
            assert value.type.int_width == size
            if size == 32:
                value = self.ir.zext(value, self.i64)
            # TODO: probably a full-width reconstructed store is better
        else:
            assert value.type.int_width == self.reg_sizes[name]
        self.ir.store(value, reg_ptr)

    def op_mem(self, op: X86Op) -> Value:
        assert op.type == CS_OP_MEM

        ir = self.ir
        addr = self.const64(op.mem.disp)

        base = op.mem.base
        if base != X86_REG_INVALID:
            if base == X86_REG_RIP:
                addr = ir.add(addr, self.const64(self.insn.address + self.insn.size))
            else:
                base_name: str = self.reg_name(base)  # pyright: ignore[reportAssignmentType]
                base_value = self.reg_read(base_name)
                addr = ir.add(addr, base_value)

        index = op.mem.index
        if index != X86_REG_INVALID:
            index_name: str = self.reg_name(index)  # pyright: ignore[reportAssignmentType]
            index_value = self.reg_read(index_name)
            scale_value = self.const64(op.mem.scale)
            addr = ir.add(addr, ir.mul(index_value, scale_value))

        if op.mem.segment == X86_REG_GS:
            addr = ir.add(addr, self.reg_read("gsbase"))

        return addr

    def op_read(self, index: int) -> Value:
        op: X86Op = self.insn.operands[index]
        if op.type == CS_OP_REG:
            name = self.reg_name(op.reg)  # pyright: ignore[reportAssignmentType]
            return self.reg_read(name)
        if op.type == CS_OP_IMM:
            # TODO: is the sign handled correctly?
            return self.const_n(op.imm, op.size * 8)
        if op.type == CS_OP_MEM:
            addr = self.op_mem(op)
            return self.mem_read(addr, self.types.int_n(op.size * 8))
        assert False, "unreachable"

    def op_write(self, index: int, value: Value):
        op: X86Op = self.insn.operands[index]
        if op.type == CS_OP_REG:
            name = self.reg_name(op.reg)  # pyright: ignore[reportAssignmentType]
            self.reg_write(name, value)
        elif op.type == CS_OP_IMM:
            raise ValueError("Cannot write to CS_OP_IMM")
        elif op.type == CS_OP_MEM:
            addr = self.op_mem(op)
            assert value.type.int_width == op.size * 8
            # TODO: narrow the write?
            self.mem_write(addr, value)

    def mem_write(self, addr: Value, value: Value):
        memory = self.function.get_param(0)
        ptr = self.ir.gep(self.types.i8, memory, [addr])
        self.ir.store(value, ptr)

    def mem_read(self, addr: Value, ty: Type):
        memory = self.function.get_param(0)
        ptr = self.ir.gep(self.types.i8, memory, [addr])
        return self.ir.load(ty, ptr)

    def lift_flags(
        self,
        lhs: Value,
        rhs: Value,
        result: Value,
    ):
        is_zero = self.ir.icmp(IntPredicate.EQ, result, result.type.constant(0))
        zf = self.ir.zext(is_zero, self.types.i8)
        self.reg_write("zf", zf)
        # TODO: other flags are not used in the sample


def binop(sem: Semantics, opcode: Opcode):
    dst = sem.op_read(0)
    src = sem.op_read(1)
    if dst.type != src.type:
        # TODO: hack?
        src = sem.ir.zext(src, dst.type)
    result = sem.ir.binop(opcode, dst, src)
    sem.op_write(0, result)
    sem.lift_flags(dst, src, result)


@semantic
def add(sem: Semantics):
    binop(sem, Opcode.Add)


@semantic
def sub(sem: Semantics):
    binop(sem, Opcode.Sub)


@semantic
def and_(sem: Semantics):
    binop(sem, Opcode.And)


@semantic
def xor(sem: Semantics):
    binop(sem, Opcode.Xor)


@semantic
def or_(sem: Semantics):
    binop(sem, Opcode.Or)


@semantic
def shl(sem: Semantics):
    binop(sem, Opcode.Shl)


@semantic
def inc(sem: Semantics):
    dst = sem.op_read(0)
    src = sem.const64(1)
    result = sem.ir.add(dst, src)
    sem.op_write(0, result)
    sem.lift_flags(dst, src, result)


@semantic
def not_(sem: Semantics):
    dst = sem.op_read(0)
    result = sem.ir.not_(dst)
    sem.op_write(0, result)


def push_impl(sem: Semantics, value: Value):
    rsp = sem.reg_read("rsp")
    rsp_sub = sem.ir.sub(rsp, sem.const64(8))
    sem.reg_write("rsp", rsp_sub)
    sem.mem_write(rsp_sub, value)


def pop_impl(sem: Semantics) -> Value:
    rsp = sem.reg_read("rsp")
    value = sem.mem_read(rsp, sem.i64)
    rsp_add = sem.ir.add(rsp, sem.const64(8))
    sem.reg_write("rsp", rsp_add)
    return value


@semantic
def push(sem: Semantics):
    push_impl(sem, sem.op_read(0))


@semantic
def pop(sem: Semantics):
    sem.op_write(0, pop_impl(sem))


@semantic
def pushfq(sem: Semantics):
    ir = sem.ir
    zf = sem.reg_read("zf")
    value = ir.shl(ir.zext(zf, sem.i64), sem.const64(6))
    push_impl(sem, value)


@semantic
def popfq(sem: Semantics):
    ir = sem.ir
    value = pop_impl(sem)
    zf = ir.trunc(ir.lshr(value, sem.const64(6)), sem.types.i1)
    sem.reg_write("zf", ir.zext(zf, sem.types.i8))


@semantic
def mov(sem: Semantics):
    value = sem.op_read(1)
    sem.op_write(0, value)


@semantic
def lea(sem: Semantics):
    src = sem.op_mem(sem.insn.operands[1])
    sem.op_write(0, src)


@semantic
def cmp(sem: Semantics):
    dst = sem.op_read(0)
    src = sem.op_read(1)
    result = sem.ir.sub(dst, src)
    sem.lift_flags(dst, src, result)


def flag_cond(sem: Semantics, flag_name: str, flag_expected: bool):
    flag = sem.reg_read(flag_name)
    return sem.ir.icmp(
        IntPredicate.NE if flag_expected else IntPredicate.EQ, flag, sem.const_n(0, 8)
    )


@semantic
def cmovne(sem: Semantics):
    cond = flag_cond(sem, "zf", False)
    value = sem.ir.select(cond, sem.op_read(1), sem.op_read(0))
    sem.op_write(0, value)


def jcc(sem: Semantics, flag_name: str, flag_expected: bool):

    brtrue = sem.insn.operands[0].imm
    brfalse = sem.insn.address + sem.insn.size
    sem.ir.cond_br(
        flag_cond(sem, flag_name, flag_expected),
        sem.get_or_create_block(brtrue),
        sem.get_or_create_block(brfalse),
    )

    src = sem.insn.address
    return [
        Successor(src, sem.const64(brtrue)),
        Successor(src, sem.const64(brfalse)),
    ]


@semantic
def je(sem: Semantics) -> list[Successor]:
    return jcc(sem, "zf", True)


@semantic
def jne(sem: Semantics) -> list[Successor]:
    return jcc(sem, "zf", False)


@semantic
def jmp(sem: Semantics) -> list[Successor]:
    dst = sem.op_read(0)
    if dst.is_constant:
        sem.ir.br(sem.get_or_create_block(dst.const_zext_value))
    else:
        sem.ir.call(sem.indirect_jmp, [dst])
        sem.ir.ret_void()
    return [Successor(sem.insn.address, dst)]


@semantic
def ret(sem: Semantics):
    sem.ir.ret_void()
    return []


@semantic
def nop(sem: Semantics):
    pass


def lift(module: Module, pe: PE, start: int, *, verbose=True):
    image_base = pe.OPTIONAL_HEADER.ImageBase  # pyright: ignore[reportOptionalMemberAccess, reportAttributeAccessIssue]
    image_size = pe.OPTIONAL_HEADER.SizeOfImage  # pyright: ignore[reportOptionalMemberAccess, reportAttributeAccessIssue]
    sem = Semantics(module, verbose=verbose)
    lifted_fn = sem.begin(start)

    queue: Queue[Successor] = Queue()
    queue.put(Successor(0, sem.const64(start)))
    visited: set[Value] = set()
    while not queue.empty():
        src, dst = queue.get()

        if not dst.is_constant:
            if sem.verbose:
                print(f"; non-constant branch destination: {hex(src)} -> {dst}")
            # TODO: jmp reg
            continue

        if dst in visited:
            continue
        visited.add(dst)

        va = dst.const_zext_value
        assert va >= image_base and va < image_base + image_size
        code = pe.get_data(va - image_base, 15)
        successors = sem.lift_bytes(va, code)
        for successor in successors:
            if successor.dst in visited:
                continue
            queue.put(successor)

    sem.module.verify_or_raise()
    return lifted_fn


if __name__ == "__main__":
    with create_context() as context:
        with context.create_module("lifted") as module:
            vm_entry = lift(module, PE("crackme.exe"), 0x140017A41)
            print(vm_entry)
            cfg = lift(module, PE("tests/cfg.exe"), 0x140001000)
            print(cfg)
