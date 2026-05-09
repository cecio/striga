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


RFLAGS_BITS = {
    "cf": 0,
    "pf": 2,
    "af": 4,
    "zf": 6,
    "sf": 7,
    "of": 11,
}


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
            if r8h:
                self.subregs[r8h] = (r64, 8, 8)

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

        helper_ty = types.function(types.void, [types.i64])
        undefined_flag_ty = types.function(types.i8, [types.i64])
        # TODO: update llvm-nanobind to add module.get_or_insert_function
        self.indirect_jmp = self.get_or_insert_helper("indirect_jmp", helper_ty)
        self.call_handler = self.get_or_insert_helper("call", helper_ty)
        self.ret_handler = self.get_or_insert_helper("ret", helper_ty)
        self.undefined_flags = {
            name: self.get_or_insert_helper(f"undefined_{name}", undefined_flag_ty)
            for name in RFLAGS_BITS
        }

        # Set per function lifting
        self.insn_blocks: dict[int, BasicBlock] = {}
        self.function: Function
        self.reg_ptrs: dict[str, Value] = {}

        # Set per instruction
        self.ir: Builder
        self.insn: CsInsn

    def get_or_insert_helper(self, name: str, ty: Type) -> Function:
        """Declare a user-provided control-transfer helper if needed."""
        fn = self.module.get_function(name)
        if fn is None:
            fn = self.module.add_function(name, ty)
        return fn

    def const64(self, val: int, sign_extend=False):
        return self.const_n(val, 64, sign_extend)

    def const_n(self, val: int, bits: int, sign_extend=False):
        return self.types.int_n(bits).constant(val, sign_extend)

    def resize_int(self, value: Value, ty: Type, *, sign_extend=False) -> Value:
        """Resize an integer value to ``ty`` with trunc/zext/sext as needed."""
        if value.type == ty:
            return value
        if value.type.int_width > ty.int_width:
            return self.ir.trunc(value, ty)
        if sign_extend:
            return self.ir.sext(value, ty)
        return self.ir.zext(value, ty)

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
            self.insn_blocks = {}
            entry = fn.entry_block
            assert entry.name == "initialize", (
                "unexpected basic block for lifted function"
            )
            for block in fn.basic_blocks:
                if block.name.startswith("insn_"):
                    self.insn_blocks[int(block.name.removeprefix("insn_"), 16)] = block
            for insn in entry.instructions:
                if (
                    insn.opcode == Opcode.GetElementPtr
                    and insn.gep_source_element_type == self.state_ty
                ):
                    assert insn.name in self.reg_types, "unexpected GEP"
                    self.reg_ptrs[insn.name] = insn
            assert self.reg_ptrs.keys() == self.reg_types.keys(), (
                "failed to reconstruct register pointers"
            )
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

    def lift_bytes(self, address: int, code: bytes):
        insn = self.cs_disasm(address, code)
        if self.verbose:
            print(";", hex(insn.address), insn.mnemonic, insn.op_str)

        # Get or create - the block may already exist as a branch target.
        # If the block is already populated, this function has already been
        # lifted in this module; do not append a second terminator.
        block = self.get_or_create_block(address)
        assert block.first_instruction
        if block.first_instruction.opcode == Opcode.Unreachable:
            block.first_instruction.erase_from_parent()
        else:
            return []

        with block.create_builder() as ir:
            self.ir = ir
            self.insn = insn
            # Intentional: RIP records the current instruction, not the next PC.
            # Each lifted instruction owns writing its own address.
            self.reg_write("rip", self.const64(address))
            handler = _semantics.get(insn.mnemonic)
            if not handler:
                raise NotImplementedError(insn.mnemonic)

            successors = handler(self)
            if successors is None:
                # Linear fallthrough - handler didn't emit a terminator.
                fallthrough = address + insn.size
                ir.br(self.get_or_create_block(fallthrough))
                successors = [Successor(address, self.const64(fallthrough))]

            self.module.verify_or_raise()
            return successors

    def reg_name(self, reg_id: int) -> str:
        return self.insn.reg_name(reg_id)  # pyright: ignore[reportReturnType]

    def reg_read(self, name: str):
        reg_ptr = self.reg_ptrs.get(name)
        if reg_ptr is not None:
            return self.ir.load(self.reg_types[name], reg_ptr)

        full_name, size, bit_offset = self.subregs[name]
        full = self.ir.load(self.reg_types[full_name], self.reg_ptrs[full_name])
        if bit_offset:
            full = self.ir.lshr(full, self.const64(bit_offset))
        return self.ir.trunc(full, self.types.int_n(size))

    def reg_write(self, name: str, value: Value):
        reg_ptr = self.reg_ptrs.get(name)
        if reg_ptr is not None:
            assert value.type.int_width == self.reg_sizes[name]
            self.ir.store(value, reg_ptr)
            return

        full_name, size, bit_offset = self.subregs[name]
        assert value.type.int_width == size
        full_ptr = self.reg_ptrs[full_name]

        # x86-64 writes to r32 zero-extend into the enclosing r64 register.
        if size == 32:
            self.ir.store(self.ir.zext(value, self.i64), full_ptr)
            return

        # Narrow writes update only the addressed bits of the full register.
        mask = ((1 << size) - 1) << bit_offset
        full = self.ir.load(self.i64, full_ptr)
        cleared = self.ir.and_(full, self.const64(~mask))
        widened = self.ir.zext(value, self.i64)
        if bit_offset:
            widened = self.ir.shl(widened, self.const64(bit_offset))
        self.ir.store(self.ir.or_(cleared, widened), full_ptr)

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
        store = self.ir.store(value, ptr)
        store.set_inst_alignment(1)

    def mem_read(self, addr: Value, ty: Type):
        memory = self.function.get_param(0)
        ptr = self.ir.gep(self.types.i8, memory, [addr])
        load = self.ir.load(ty, ptr)
        load.set_inst_alignment(1)
        return load

    def bool_to_flag(self, value: Value) -> Value:
        """Convert an LLVM i1 flag predicate to the i8 state representation."""
        if value.type == self.types.i8:
            return value
        assert value.type == self.types.i1
        return self.ir.zext(value, self.types.i8)

    def flag_bool(self, name: str) -> Value:
        """Read an i8 flag from state as an LLVM i1 predicate."""
        return self.ir.icmp(IntPredicate.NE, self.reg_read(name), self.const_n(0, 8))

    def write_flag(self, name: str, value: Value):
        self.reg_write(name, self.bool_to_flag(value))

    def write_flag_if(self, cond: Value, name: str, value: Value):
        """Update a flag only when ``cond`` is true; otherwise preserve it."""
        assert cond.type == self.types.i1
        old_value = self.reg_read(name)
        new_value = self.bool_to_flag(value)
        self.reg_write(name, self.ir.select(cond, new_value, old_value))

    def undefined_flag(self, name: str) -> Value:
        """Call the per-flag helper for architecturally undefined flags."""
        helper = self.undefined_flags[name]
        return self.ir.call(helper, [self.const64(self.insn.address)])

    def undefined_flag_bool(self, name: str) -> Value:
        return self.ir.icmp(
            IntPredicate.NE, self.undefined_flag(name), self.const_n(0, 8)
        )

    def write_undef_flag(self, name: str):
        self.write_flag(name, self.undefined_flag(name))

    def write_undef_flag_if(self, cond: Value, name: str):
        self.write_flag_if(cond, name, self.undefined_flag(name))

    def result_is_zero(self, result: Value) -> Value:
        return self.ir.icmp(IntPredicate.EQ, result, result.type.constant(0))

    def result_sign_bit(self, result: Value) -> Value:
        sign_shift = result.type.constant(result.type.int_width - 1)
        return self.ir.trunc(self.ir.lshr(result, sign_shift), self.types.i1)

    def result_parity_even(self, result: Value) -> Value:
        """Return PF: even parity in the low byte of ``result``."""
        low = self.resize_int(result, self.types.i8)
        x = self.ir.xor(low, self.ir.lshr(low, self.const_n(4, 8)))
        x = self.ir.xor(x, self.ir.lshr(x, self.const_n(2, 8)))
        x = self.ir.xor(x, self.ir.lshr(x, self.const_n(1, 8)))
        return self.ir.icmp(
            IntPredicate.EQ,
            self.ir.and_(x, self.const_n(1, 8)),
            self.const_n(0, 8),
        )

    def aux_carry(self, lhs: Value, rhs: Value, result: Value) -> Value:
        nibble_carry = self.ir.and_(
            self.ir.xor(self.ir.xor(lhs, rhs), result),
            lhs.type.constant(0x10),
        )
        return self.ir.icmp(IntPredicate.NE, nibble_carry, lhs.type.constant(0))

    def add_overflow(self, lhs: Value, rhs: Value, result: Value) -> Value:
        sign_mask = lhs.type.constant(-(1 << (lhs.type.int_width - 1)))
        overflow_bits = self.ir.and_(
            self.ir.xor(lhs, result),
            self.ir.xor(rhs, result),
        )
        return self.ir.icmp(
            IntPredicate.NE,
            self.ir.and_(overflow_bits, sign_mask),
            lhs.type.constant(0),
        )

    def sub_overflow(self, lhs: Value, rhs: Value, result: Value) -> Value:
        sign_mask = lhs.type.constant(-(1 << (lhs.type.int_width - 1)))
        overflow_bits = self.ir.and_(
            self.ir.xor(lhs, rhs),
            self.ir.xor(lhs, result),
        )
        return self.ir.icmp(
            IntPredicate.NE,
            self.ir.and_(overflow_bits, sign_mask),
            lhs.type.constant(0),
        )

    def write_common_arith_flags(self, lhs: Value, rhs: Value, result: Value):
        self.write_flag("pf", self.result_parity_even(result))
        self.write_flag("af", self.aux_carry(lhs, rhs, result))
        self.write_flag("zf", self.result_is_zero(result))
        self.write_flag("sf", self.result_sign_bit(result))

    def write_add_flags(
        self,
        lhs: Value,
        rhs: Value,
        result: Value,
        *,
        write_cf: bool = True,
    ):
        if write_cf:
            self.write_flag("cf", self.ir.icmp(IntPredicate.ULT, result, lhs))
        self.write_common_arith_flags(lhs, rhs, result)
        self.write_flag("of", self.add_overflow(lhs, rhs, result))

    def write_sub_flags(self, lhs: Value, rhs: Value, result: Value):
        self.write_flag("cf", self.ir.icmp(IntPredicate.ULT, lhs, rhs))
        self.write_common_arith_flags(lhs, rhs, result)
        self.write_flag("of", self.sub_overflow(lhs, rhs, result))

    def write_logical_flags(self, result: Value):
        false = self.const_n(0, 1)
        self.write_flag("cf", false)
        self.write_flag("pf", self.result_parity_even(result))
        self.write_undef_flag("af")
        self.write_flag("zf", self.result_is_zero(result))
        self.write_flag("sf", self.result_sign_bit(result))
        self.write_flag("of", false)

    def write_shl_flags(self, lhs: Value, count: Value, result: Value):
        width = lhs.type.int_width
        count_nonzero = self.ir.icmp(IntPredicate.NE, count, count.type.constant(0))
        count_one = self.ir.icmp(IntPredicate.EQ, count, count.type.constant(1))
        if width < 32:
            count_in_range = self.ir.icmp(
                IntPredicate.ULT, count, count.type.constant(width)
            )
        else:
            count_in_range = self.const_n(1, 1)

        cf_defined = self.ir.and_(count_nonzero, count_in_range)
        safe_count = self.ir.select(cf_defined, count, count.type.constant(1))
        cf_shift = self.ir.sub(count.type.constant(width), safe_count)
        cf = self.ir.trunc(self.ir.lshr(lhs, cf_shift), self.types.i1)
        if width < 32:
            cf = self.ir.select(count_in_range, cf, self.undefined_flag_bool("cf"))
        self.write_flag_if(count_nonzero, "cf", cf)

        of_for_one = self.ir.xor(
            self.result_sign_bit(lhs), self.result_sign_bit(result)
        )
        of = self.ir.select(count_one, of_for_one, self.undefined_flag_bool("of"))
        self.write_flag_if(count_nonzero, "of", of)

        self.write_flag_if(count_nonzero, "pf", self.result_parity_even(result))
        self.write_undef_flag_if(count_nonzero, "af")
        self.write_flag_if(count_nonzero, "zf", self.result_is_zero(result))
        self.write_flag_if(count_nonzero, "sf", self.result_sign_bit(result))

    def write_shr_flags(self, lhs: Value, count: Value, result: Value):
        width = lhs.type.int_width
        count_nonzero = self.ir.icmp(IntPredicate.NE, count, count.type.constant(0))
        count_one = self.ir.icmp(IntPredicate.EQ, count, count.type.constant(1))
        if width < 32:
            count_in_range = self.ir.icmp(
                IntPredicate.ULT, count, count.type.constant(width)
            )
        else:
            count_in_range = self.const_n(1, 1)

        cf_defined = self.ir.and_(count_nonzero, count_in_range)
        safe_count = self.ir.select(cf_defined, count, count.type.constant(1))
        cf_shift = self.ir.sub(safe_count, count.type.constant(1))
        cf = self.ir.trunc(self.ir.lshr(lhs, cf_shift), self.types.i1)
        if width < 32:
            cf = self.ir.select(count_in_range, cf, self.undefined_flag_bool("cf"))
        self.write_flag_if(count_nonzero, "cf", cf)

        of = self.ir.select(
            count_one, self.result_sign_bit(lhs), self.undefined_flag_bool("of")
        )
        self.write_flag_if(count_nonzero, "of", of)

        self.write_flag_if(count_nonzero, "pf", self.result_parity_even(result))
        self.write_undef_flag_if(count_nonzero, "af")
        self.write_flag_if(count_nonzero, "zf", self.result_is_zero(result))
        self.write_flag_if(count_nonzero, "sf", self.result_sign_bit(result))

    def write_sar_flags(self, lhs: Value, count: Value, result: Value):
        width = lhs.type.int_width
        count_nonzero = self.ir.icmp(IntPredicate.NE, count, count.type.constant(0))
        count_one = self.ir.icmp(IntPredicate.EQ, count, count.type.constant(1))
        if width < 32:
            count_in_range = self.ir.icmp(
                IntPredicate.ULT, count, count.type.constant(width)
            )
        else:
            count_in_range = self.const_n(1, 1)

        safe_count = self.ir.select(count_in_range, count, count.type.constant(1))
        cf_shift = self.ir.sub(safe_count, count.type.constant(1))
        shifted_out = self.ir.trunc(self.ir.lshr(lhs, cf_shift), self.types.i1)
        cf = self.ir.select(count_in_range, shifted_out, self.result_sign_bit(lhs))
        self.write_flag_if(count_nonzero, "cf", cf)

        false = self.const_n(0, 1)
        of = self.ir.select(count_one, false, self.undefined_flag_bool("of"))
        self.write_flag_if(count_nonzero, "of", of)

        self.write_flag_if(count_nonzero, "pf", self.result_parity_even(result))
        self.write_undef_flag_if(count_nonzero, "af")
        self.write_flag_if(count_nonzero, "zf", self.result_is_zero(result))
        self.write_flag_if(count_nonzero, "sf", self.result_sign_bit(result))

    def pack_rflags(self) -> Value:
        value = self.const64(1 << 1)  # Reserved bit 1 is always set.
        for name, bit in RFLAGS_BITS.items():
            flag = self.ir.zext(self.flag_bool(name), self.i64)
            if bit:
                flag = self.ir.shl(flag, self.const64(bit))
            value = self.ir.or_(value, flag)
        return value

    def unpack_rflags(self, value: Value):
        value = self.resize_int(value, self.i64)
        for name, bit in RFLAGS_BITS.items():
            flag = self.ir.trunc(self.ir.lshr(value, self.const64(bit)), self.types.i1)
            self.write_flag(name, flag)


ArithFlagWriter: TypeAlias = Callable[[Semantics, Value, Value, Value], None]


def arith_binop(sem: Semantics, opcode: Opcode, write_flags: ArithFlagWriter):
    dst = sem.op_read(0)
    src = sem.resize_int(sem.op_read(1), dst.type)
    result = sem.ir.binop(opcode, dst, src)
    sem.op_write(0, result)
    write_flags(sem, dst, src, result)


def logical_binop(sem: Semantics, opcode: Opcode):
    dst = sem.op_read(0)
    src = sem.resize_int(sem.op_read(1), dst.type)
    result = sem.ir.binop(opcode, dst, src)
    sem.op_write(0, result)
    sem.write_logical_flags(result)


@semantic
def add(sem: Semantics):
    arith_binop(sem, Opcode.Add, Semantics.write_add_flags)


@semantic
def sub(sem: Semantics):
    arith_binop(sem, Opcode.Sub, Semantics.write_sub_flags)


@semantic
def and_(sem: Semantics):
    logical_binop(sem, Opcode.And)


@semantic
def xor(sem: Semantics):
    logical_binop(sem, Opcode.Xor)


@semantic
def or_(sem: Semantics):
    logical_binop(sem, Opcode.Or)


def masked_shift_count(sem: Semantics, value: Value, width: int) -> Value:
    count = sem.resize_int(value, sem.types.int_n(width))
    count_mask = 63 if width == 64 else 31
    return sem.ir.and_(count, count.type.constant(count_mask))


@semantic
def shl(sem: Semantics):
    dst = sem.op_read(0)
    width = dst.type.int_width
    count = masked_shift_count(sem, sem.op_read(1), width)

    # x86 masks shift counts before executing the shift. LLVM shifts by a
    # count >= the bit width are poison, so narrow operands need an extra guard.
    if width < 32:
        in_range = sem.ir.icmp(IntPredicate.ULT, count, dst.type.constant(width))
        safe_count = sem.ir.select(in_range, count, dst.type.constant(0))
        shifted = sem.ir.shl(dst, safe_count)
        result = sem.ir.select(in_range, shifted, dst.type.constant(0))
    else:
        result = sem.ir.shl(dst, count)

    sem.op_write(0, result)
    sem.write_shl_flags(dst, count, result)


@semantic
def shr(sem: Semantics):
    dst = sem.op_read(0)
    width = dst.type.int_width
    count = masked_shift_count(sem, sem.op_read(1), width)

    if width < 32:
        in_range = sem.ir.icmp(IntPredicate.ULT, count, dst.type.constant(width))
        safe_count = sem.ir.select(in_range, count, dst.type.constant(0))
        shifted = sem.ir.lshr(dst, safe_count)
        result = sem.ir.select(in_range, shifted, dst.type.constant(0))
    else:
        result = sem.ir.lshr(dst, count)

    sem.op_write(0, result)
    sem.write_shr_flags(dst, count, result)


@semantic
def sar(sem: Semantics):
    dst = sem.op_read(0)
    width = dst.type.int_width
    count = masked_shift_count(sem, sem.op_read(1), width)

    if width < 32:
        in_range = sem.ir.icmp(IntPredicate.ULT, count, dst.type.constant(width))
        safe_count = sem.ir.select(in_range, count, dst.type.constant(0))
        shifted = sem.ir.ashr(dst, safe_count)
        sign_filled = sem.ir.select(
            sem.result_sign_bit(dst), dst.type.constant(-1), dst.type.constant(0)
        )
        result = sem.ir.select(in_range, shifted, sign_filled)
    else:
        result = sem.ir.ashr(dst, count)

    sem.op_write(0, result)
    sem.write_sar_flags(dst, count, result)


@semantic
def inc(sem: Semantics):
    dst = sem.op_read(0)
    src = dst.type.constant(1)
    result = sem.ir.add(dst, src)
    sem.op_write(0, result)
    sem.write_add_flags(dst, src, result, write_cf=False)


def write_undef_arith_flags(sem: Semantics):
    sem.write_undef_flag("cf")
    sem.write_undef_flag("of")
    sem.write_undef_flag("sf")
    sem.write_undef_flag("zf")
    sem.write_undef_flag("af")
    sem.write_undef_flag("pf")


def write_mul_flags(sem: Semantics, overflow: Value):
    sem.write_flag("cf", overflow)
    sem.write_flag("of", overflow)
    sem.write_undef_flag("sf")
    sem.write_undef_flag("zf")
    sem.write_undef_flag("af")
    sem.write_undef_flag("pf")


def signed_wide_mul(sem: Semantics, lhs: Value, rhs: Value) -> tuple[Value, Value]:
    wide_ty = sem.types.int_n(lhs.type.int_width * 2)
    wide_lhs = sem.resize_int(lhs, wide_ty, sign_extend=True)
    wide_rhs = sem.resize_int(rhs, wide_ty, sign_extend=True)
    product = sem.ir.mul(wide_lhs, wide_rhs)
    truncated = sem.ir.trunc(product, lhs.type)
    overflow = sem.ir.icmp(
        IntPredicate.NE,
        sem.ir.sext(truncated, wide_ty),
        product,
    )
    return product, overflow


def unsigned_wide_mul(sem: Semantics, lhs: Value, rhs: Value) -> tuple[Value, Value]:
    wide_ty = sem.types.int_n(lhs.type.int_width * 2)
    wide_lhs = sem.resize_int(lhs, wide_ty)
    wide_rhs = sem.resize_int(rhs, wide_ty)
    product = sem.ir.mul(wide_lhs, wide_rhs)
    truncated = sem.ir.trunc(product, lhs.type)
    overflow = sem.ir.icmp(
        IntPredicate.NE,
        sem.ir.zext(truncated, wide_ty),
        product,
    )
    return product, overflow


@semantic
def imul(sem: Semantics):
    if len(sem.insn.operands) == 1:
        src = sem.op_read(0)
        width = src.type.int_width
        match width:
            case 8:
                lhs = sem.reg_read("al")
                product, overflow = signed_wide_mul(sem, lhs, src)
                sem.reg_write("ax", product)
            case 16:
                lhs = sem.reg_read("ax")
                product, overflow = signed_wide_mul(sem, lhs, src)
                sem.reg_write("ax", sem.ir.trunc(product, sem.types.i16))
                sem.reg_write(
                    "dx",
                    sem.ir.trunc(
                        sem.ir.lshr(product, sem.const_n(16, 32)), sem.types.i16
                    ),
                )
            case 32:
                lhs = sem.reg_read("eax")
                product, overflow = signed_wide_mul(sem, lhs, src)
                sem.reg_write("eax", sem.ir.trunc(product, sem.types.i32))
                sem.reg_write(
                    "edx",
                    sem.ir.trunc(
                        sem.ir.lshr(product, sem.const_n(32, 64)), sem.types.i32
                    ),
                )
            case 64:
                lhs = sem.reg_read("rax")
                product, overflow = signed_wide_mul(sem, lhs, src)
                sem.reg_write("rax", sem.ir.trunc(product, sem.i64))
                sem.reg_write(
                    "rdx",
                    sem.ir.trunc(sem.ir.lshr(product, sem.const_n(64, 128)), sem.i64),
                )
            case _:
                raise NotImplementedError(f"imul width {width}")
        write_mul_flags(sem, overflow)
        return

    if len(sem.insn.operands) == 2:
        lhs = sem.op_read(0)
        rhs = sem.resize_int(sem.op_read(1), lhs.type, sign_extend=True)
    elif len(sem.insn.operands) == 3:
        lhs = sem.resize_int(
            sem.op_read(1), sem.types.int_n(sem.insn.operands[0].size * 8)
        )
        rhs = sem.resize_int(sem.op_read(2), lhs.type, sign_extend=True)
    else:
        raise NotImplementedError("imul operand count")

    product, overflow = signed_wide_mul(sem, lhs, rhs)
    sem.op_write(0, sem.ir.trunc(product, lhs.type))
    write_mul_flags(sem, overflow)


@semantic
def mul(sem: Semantics):
    src = sem.op_read(0)
    width = src.type.int_width
    match width:
        case 8:
            lhs = sem.reg_read("al")
            product, overflow = unsigned_wide_mul(sem, lhs, src)
            sem.reg_write("ax", product)
        case 16:
            lhs = sem.reg_read("ax")
            product, overflow = unsigned_wide_mul(sem, lhs, src)
            sem.reg_write("ax", sem.ir.trunc(product, sem.types.i16))
            sem.reg_write(
                "dx",
                sem.ir.trunc(sem.ir.lshr(product, sem.const_n(16, 32)), sem.types.i16),
            )
        case 32:
            lhs = sem.reg_read("eax")
            product, overflow = unsigned_wide_mul(sem, lhs, src)
            sem.reg_write("eax", sem.ir.trunc(product, sem.types.i32))
            sem.reg_write(
                "edx",
                sem.ir.trunc(sem.ir.lshr(product, sem.const_n(32, 64)), sem.types.i32),
            )
        case 64:
            lhs = sem.reg_read("rax")
            product, overflow = unsigned_wide_mul(sem, lhs, src)
            sem.reg_write("rax", sem.ir.trunc(product, sem.i64))
            sem.reg_write(
                "rdx", sem.ir.trunc(sem.ir.lshr(product, sem.const_n(64, 128)), sem.i64)
            )
        case _:
            raise NotImplementedError(f"mul width {width}")
    write_mul_flags(sem, overflow)


def divmod_wide(
    sem: Semantics, high: Value, low: Value, divisor: Value, *, signed=False
):
    wide_ty = sem.types.int_n(divisor.type.int_width * 2)
    wide_high = sem.resize_int(high, wide_ty)
    wide_low = sem.resize_int(low, wide_ty)
    dividend = sem.ir.or_(
        sem.ir.shl(wide_high, wide_ty.constant(divisor.type.int_width)), wide_low
    )
    wide_divisor = sem.resize_int(divisor, wide_ty, sign_extend=signed)
    if signed:
        return sem.ir.sdiv(dividend, wide_divisor), sem.ir.srem(dividend, wide_divisor)
    return sem.ir.udiv(dividend, wide_divisor), sem.ir.urem(dividend, wide_divisor)


@semantic
def div(sem: Semantics):
    src = sem.op_read(0)
    match src.type.int_width:
        case 8:
            quotient, remainder = divmod_wide(
                sem, sem.reg_read("ah"), sem.reg_read("al"), src
            )
            sem.reg_write("al", sem.ir.trunc(quotient, sem.types.i8))
            sem.reg_write("ah", sem.ir.trunc(remainder, sem.types.i8))
        case 16:
            quotient, remainder = divmod_wide(
                sem, sem.reg_read("dx"), sem.reg_read("ax"), src
            )
            sem.reg_write("ax", sem.ir.trunc(quotient, sem.types.i16))
            sem.reg_write("dx", sem.ir.trunc(remainder, sem.types.i16))
        case 32:
            quotient, remainder = divmod_wide(
                sem, sem.reg_read("edx"), sem.reg_read("eax"), src
            )
            sem.reg_write("eax", sem.ir.trunc(quotient, sem.types.i32))
            sem.reg_write("edx", sem.ir.trunc(remainder, sem.types.i32))
        case 64:
            quotient, remainder = divmod_wide(
                sem, sem.reg_read("rdx"), sem.reg_read("rax"), src
            )
            sem.reg_write("rax", sem.ir.trunc(quotient, sem.i64))
            sem.reg_write("rdx", sem.ir.trunc(remainder, sem.i64))
        case width:
            raise NotImplementedError(f"div width {width}")
    write_undef_arith_flags(sem)


@semantic
def idiv(sem: Semantics):
    src = sem.op_read(0)
    match src.type.int_width:
        case 8:
            quotient, remainder = divmod_wide(
                sem, sem.reg_read("ah"), sem.reg_read("al"), src, signed=True
            )
            sem.reg_write("al", sem.ir.trunc(quotient, sem.types.i8))
            sem.reg_write("ah", sem.ir.trunc(remainder, sem.types.i8))
        case 16:
            quotient, remainder = divmod_wide(
                sem, sem.reg_read("dx"), sem.reg_read("ax"), src, signed=True
            )
            sem.reg_write("ax", sem.ir.trunc(quotient, sem.types.i16))
            sem.reg_write("dx", sem.ir.trunc(remainder, sem.types.i16))
        case 32:
            quotient, remainder = divmod_wide(
                sem, sem.reg_read("edx"), sem.reg_read("eax"), src, signed=True
            )
            sem.reg_write("eax", sem.ir.trunc(quotient, sem.types.i32))
            sem.reg_write("edx", sem.ir.trunc(remainder, sem.types.i32))
        case 64:
            quotient, remainder = divmod_wide(
                sem, sem.reg_read("rdx"), sem.reg_read("rax"), src, signed=True
            )
            sem.reg_write("rax", sem.ir.trunc(quotient, sem.i64))
            sem.reg_write("rdx", sem.ir.trunc(remainder, sem.i64))
        case width:
            raise NotImplementedError(f"idiv width {width}")
    write_undef_arith_flags(sem)


@semantic
def not_(sem: Semantics):
    dst = sem.op_read(0)
    result = sem.ir.not_(dst)
    sem.op_write(0, result)


def bit_test_base_and_mask(sem: Semantics) -> tuple[Value, Value, Value | None]:
    base_op = sem.insn.operands[0]
    bit_op = sem.insn.operands[1]
    width = base_op.size * 8
    ty = sem.types.int_n(width)
    bit = sem.resize_int(sem.op_read(1), sem.i64)

    if base_op.type == CS_OP_MEM:
        bit_index = sem.ir.urem(bit, sem.const64(width))
        element_index = sem.ir.udiv(bit, sem.const64(width))
        element_offset = sem.ir.mul(element_index, sem.const64(base_op.size))
        addr = sem.ir.add(sem.op_mem(base_op), element_offset)
        base = sem.mem_read(addr, ty)
    else:
        addr = None
        base = sem.op_read(0)
        bit_index = sem.resize_int(bit, base.type)
        bit_index = sem.ir.urem(bit_index, base.type.constant(width))

    bit_index = sem.resize_int(bit_index, ty)
    mask = sem.ir.shl(ty.constant(1), bit_index)
    _ = bit_op  # Keep Capstone's operand detail access local to this helper.
    return base, mask, addr


def write_bit_test_flags(sem: Semantics, base: Value, mask: Value):
    sem.write_flag(
        "cf",
        sem.ir.icmp(IntPredicate.NE, sem.ir.and_(base, mask), base.type.constant(0)),
    )
    sem.write_undef_flag("of")
    sem.write_undef_flag("sf")
    sem.write_undef_flag("af")
    sem.write_undef_flag("pf")


@semantic
def bt(sem: Semantics):
    base, mask, _ = bit_test_base_and_mask(sem)
    write_bit_test_flags(sem, base, mask)


@semantic
def btr(sem: Semantics):
    base, mask, addr = bit_test_base_and_mask(sem)
    result = sem.ir.and_(base, sem.ir.not_(mask))
    write_bit_test_flags(sem, base, mask)
    if addr is None:
        sem.op_write(0, result)
    else:
        sem.mem_write(addr, result)


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
    push_impl(sem, sem.pack_rflags())


@semantic
def popfq(sem: Semantics):
    sem.unpack_rflags(pop_impl(sem))


@semantic
def mov(sem: Semantics):
    value = sem.op_read(1)
    sem.op_write(0, value)


@semantic
def movabs(sem: Semantics):
    mov(sem)


@semantic
def movzx(sem: Semantics):
    src = sem.op_read(1)
    dst_ty = sem.types.int_n(sem.insn.operands[0].size * 8)
    sem.op_write(0, sem.resize_int(src, dst_ty))


@semantic
def movsx(sem: Semantics):
    src = sem.op_read(1)
    dst_ty = sem.types.int_n(sem.insn.operands[0].size * 8)
    sem.op_write(0, sem.resize_int(src, dst_ty, sign_extend=True))


@semantic
def movsxd(sem: Semantics):
    movsx(sem)


@semantic
def lea(sem: Semantics):
    src = sem.op_mem(sem.insn.operands[1])
    dst_ty = sem.types.int_n(sem.insn.operands[0].size * 8)
    sem.op_write(0, sem.resize_int(src, dst_ty))


@semantic
def cbw(sem: Semantics):
    sem.reg_write("ax", sem.ir.sext(sem.reg_read("al"), sem.types.i16))


@semantic
def cwde(sem: Semantics):
    sem.reg_write("eax", sem.ir.sext(sem.reg_read("ax"), sem.types.i32))


@semantic
def cdqe(sem: Semantics):
    sem.reg_write("rax", sem.ir.sext(sem.reg_read("eax"), sem.i64))


@semantic
def cwd(sem: Semantics):
    ax = sem.reg_read("ax")
    sem.reg_write("dx", sem.ir.ashr(ax, sem.types.i16.constant(15)))


@semantic
def cdq(sem: Semantics):
    eax = sem.reg_read("eax")
    sem.reg_write("edx", sem.ir.ashr(eax, sem.types.i32.constant(31)))


@semantic
def cqo(sem: Semantics):
    rax = sem.reg_read("rax")
    sem.reg_write("rdx", sem.ir.ashr(rax, sem.const64(63)))


@semantic
def cmp(sem: Semantics):
    dst = sem.op_read(0)
    src = sem.resize_int(sem.op_read(1), dst.type)
    result = sem.ir.sub(dst, src)
    sem.write_sub_flags(dst, src, result)


@semantic
def test(sem: Semantics):
    lhs = sem.op_read(0)
    rhs = sem.resize_int(sem.op_read(1), lhs.type)
    result = sem.ir.and_(lhs, rhs)
    sem.write_logical_flags(result)


def bool_not(sem: Semantics, value: Value) -> Value:
    return sem.ir.xor(value, sem.const_n(1, 1))


def bool_eq(sem: Semantics, lhs: Value, rhs: Value) -> Value:
    return bool_not(sem, sem.ir.xor(lhs, rhs))


def cc_cond(sem: Semantics, cc: str) -> Value:
    cf = sem.flag_bool("cf")
    zf = sem.flag_bool("zf")
    sf = sem.flag_bool("sf")
    of = sem.flag_bool("of")
    pf = sem.flag_bool("pf")

    match cc:
        case "a" | "nbe":
            return sem.ir.and_(bool_not(sem, cf), bool_not(sem, zf))
        case "ae" | "nb" | "nc":
            return bool_not(sem, cf)
        case "b" | "nae" | "c":
            return cf
        case "be" | "na":
            return sem.ir.or_(cf, zf)
        case "e" | "z":
            return zf
        case "g" | "nle":
            return sem.ir.and_(bool_not(sem, zf), bool_eq(sem, sf, of))
        case "ge" | "nl":
            return bool_eq(sem, sf, of)
        case "l" | "nge":
            return sem.ir.xor(sf, of)
        case "le" | "ng":
            return sem.ir.or_(zf, sem.ir.xor(sf, of))
        case "ne" | "nz":
            return bool_not(sem, zf)
        case "no":
            return bool_not(sem, of)
        case "np" | "po":
            return bool_not(sem, pf)
        case "ns":
            return bool_not(sem, sf)
        case "o":
            return of
        case "p" | "pe":
            return pf
        case "s":
            return sf
    raise NotImplementedError(f"condition code {cc}")


def cmovcc(sem: Semantics, cc: str):
    cond = cc_cond(sem, cc)
    old_value = sem.op_read(0)
    new_value = sem.resize_int(sem.op_read(1), old_value.type)
    sem.op_write(0, sem.ir.select(cond, new_value, old_value))


@semantic
def cmove(sem: Semantics):
    cmovcc(sem, "e")


@semantic
def cmovne(sem: Semantics):
    cmovcc(sem, "ne")


def setcc(sem: Semantics, cc: str):
    sem.op_write(0, sem.ir.zext(cc_cond(sem, cc), sem.types.i8))


@semantic
def setb(sem: Semantics):
    setcc(sem, "b")


@semantic
def sete(sem: Semantics):
    setcc(sem, "e")


@semantic
def setl(sem: Semantics):
    setcc(sem, "l")


@semantic
def setne(sem: Semantics):
    setcc(sem, "ne")


def jcc(sem: Semantics, cc: str):
    brtrue = sem.insn.operands[0].imm
    brfalse = sem.insn.address + sem.insn.size
    cond = cc_cond(sem, cc)
    sem.ir.cond_br(
        cond,
        sem.get_or_create_block(brtrue),
        sem.get_or_create_block(brfalse),
    )

    src = sem.insn.address
    return [
        Successor(src, sem.const64(brtrue)),
        Successor(src, sem.const64(brfalse)),
    ]


@semantic
def ja(sem: Semantics):
    return jcc(sem, "a")


@semantic
def jae(sem: Semantics):
    return jcc(sem, "ae")


@semantic
def jb(sem: Semantics):
    return jcc(sem, "b")


@semantic
def jbe(sem: Semantics):
    return jcc(sem, "be")


@semantic
def je(sem: Semantics):
    return jcc(sem, "e")


@semantic
def jg(sem: Semantics):
    return jcc(sem, "g")


@semantic
def jge(sem: Semantics):
    return jcc(sem, "ge")


@semantic
def jl(sem: Semantics):
    return jcc(sem, "l")


@semantic
def jle(sem: Semantics):
    return jcc(sem, "le")


@semantic
def jne(sem: Semantics):
    return jcc(sem, "ne")


@semantic
def call(sem: Semantics):
    dst = sem.op_read(0)
    fallthrough = sem.insn.address + sem.insn.size
    push_impl(sem, sem.const64(fallthrough))
    sem.ir.call(sem.call_handler, [dst])
    sem.ir.br(sem.get_or_create_block(fallthrough))
    return [Successor(sem.insn.address, sem.const64(fallthrough))]


@semantic
def jmp(sem: Semantics):
    dst = sem.op_read(0)
    if dst.is_constant:
        sem.ir.br(sem.get_or_create_block(dst.const_zext_value))
    else:
        sem.ir.call(sem.indirect_jmp, [dst])
        sem.ir.ret_void()
    return [Successor(sem.insn.address, dst)]


@semantic
def ret(sem: Semantics):
    dst = pop_impl(sem)
    if sem.insn.operands:
        rsp = sem.reg_read("rsp")
        sem.reg_write("rsp", sem.ir.add(rsp, sem.const64(sem.insn.operands[0].imm)))
    sem.ir.call(sem.ret_handler, [dst])
    sem.ir.ret_void()
    return [Successor(sem.insn.address, dst)]


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
    # Keep destinations as LLVM Values instead of splitting constants into ints.
    # This keeps the worklist uniform and matches later slicing/data-flow uses.
    visited: set[Value] = set()
    while not queue.empty():
        src, dst = queue.get()

        if not dst.is_constant:
            if sem.verbose:
                print(f"; non-constant branch destination: {hex(src)} -> {dst}")
            # TODO: recover jump tables / returned-to callers
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
            riscvm_run = lift(module, PE("riscvm.exe"), 0x140001104)
            print(riscvm_run)
