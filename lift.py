import pefile
from contextlib import contextmanager
from queue import Queue

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
    X86_INS_ADD,
    X86_INS_AND,
    X86_INS_CMOVNE,
    X86_INS_INC,
    X86_INS_JMP,
    X86_INS_LEA,
    X86_INS_MOV,
    X86_INS_NOP,
    X86_INS_OR,
    X86_INS_POP,
    X86_INS_POPFQ,
    X86_INS_PUSH,
    X86_INS_PUSHFQ,
    X86_INS_RET,
    X86_INS_SUB,
    X86_INS_XOR,
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
)


class Lifter:
    def __init__(self, pe: pefile.PE, module: Module):
        self.pe = pe
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase  # pyright: ignore[reportOptionalMemberAccess, reportAttributeAccessIssue]
        self.image_size = self.pe.OPTIONAL_HEADER.SizeOfImage  # pyright: ignore[reportOptionalMemberAccess, reportAttributeAccessIssue]
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True
        self.module = module
        self.context = module.context
        types = self.context.types
        self.types = types
        self.i64 = self.types.i64

        self.reg_sizes = {
            "rax": 64,
            "rbx": 64,
            "rcx": 64,
            "rdx": 64,
            "rsi": 64,
            "rdi": 64,
            "rsp": 64,
            "rbp": 64,
            "r8": 64,
            "r9": 64,
            "r10": 64,
            "r11": 64,
            "r12": 64,
            "r13": 64,
            "r14": 64,
            "r15": 64,
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
            name: self.types.int_n(size) for name, size in self.reg_sizes.items()
        }
        self.reg_ptrs: dict[str, Value] = {}
        self.state_ty = types.struct(self.reg_types.values(), name="State")
        self.function: Function | None = None
        self.lifted_ty = types.function(types.void, [types.ptr, types.ptr])

    @staticmethod
    @contextmanager
    def create(pe: pefile.PE):
        with create_context() as context:
            with context.create_module("") as module:
                yield Lifter(pe, module)

    def cs_disasm(self, address: int, code: bytes) -> CsInsn:
        for insn in self.cs.disasm(code, address, count=1):  # ty: ignore[missing-argument, invalid-argument-type]
            return insn
        raise ValueError(f"Failed to disassemble {code.hex()}@{hex(address)}")

    def switch_function(self, name: str):
        fn = self.module.get_function(name)
        if fn is None:
            fn = self.module.add_function(name, self.lifted_ty)
            fn.linkage = Linkage.Internal
            memory, state = fn.params
            memory.name = "memory"
            state.name = "state"

            entry = fn.append_basic_block("initialize")
            assert fn.last_basic_block == entry
            with entry.create_builder() as builder:
                for i, name in enumerate(self.reg_sizes.keys()):
                    reg_ptr = builder.struct_gep(self.state_ty, state, i, name)
                    self.reg_ptrs[name] = reg_ptr
        else:
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

        self.function = fn

    def _reg_read(self, builder: Builder, name: str):
        reg_ptr = self.reg_ptrs[name]
        return builder.load(self.reg_types[name], reg_ptr)

    def _reg_write(self, builder: Builder, name: str, value: Value):
        extend_regs = {
            "eax": "rax",
            "ebx": "rbx",
            "ecx": "rcx",
            "edx": "rdx",
            "esi": "rsi",
            "edi": "rdi",
            "esp": "rsp",
            "ebp": "rbp",
            "r8d": "r8",
            "r9d": "r9",
            "r10d": "r10",
            "r11d": "r11",
            "r12d": "r12",
            "r13d": "r13",
            "r14d": "r14",
            "r15d": "r15",
        }
        extend_reg = extend_regs.get(name)
        if extend_reg:
            reg_ptr = self.reg_ptrs[extend_reg]
            assert value.type.int_width == 32
            builder.store(builder.zext(value, self.i64), reg_ptr)
        else:
            reg_ptr = self.reg_ptrs[name]
            assert value.type.int_width == self.reg_sizes[name]
            builder.store(value, reg_ptr)

    def _operand_mem(self, builder: Builder, insn: CsInsn, op: X86Op) -> Value:
        assert op.type == CS_OP_MEM

        addr = self.i64.constant(op.mem.disp)

        base = op.mem.base
        if base != X86_REG_INVALID:
            if base == X86_REG_RIP:
                addr = builder.add(addr, self.i64.constant(insn.address + insn.size))
            else:
                base_name: str = insn.reg_name(base)  # pyright: ignore[reportAssignmentType]
                base_value = self._reg_read(builder, base_name)
                addr = builder.add(addr, base_value)

        index = op.mem.index
        if index != X86_REG_INVALID:
            index_name: str = insn.reg_name(index)  # pyright: ignore[reportAssignmentType]
            index_value = self._reg_read(builder, index_name)
            scale_value = self.i64.constant(op.mem.scale)
            addr = builder.add(addr, builder.mul(index_value, scale_value))

        if op.mem.segment == X86_REG_GS:
            addr = builder.add(addr, self._reg_read(builder, "gsbase"))

        return addr

    def _operand_read(self, builder: Builder, insn: CsInsn, index: int) -> Value:
        op: X86Op = insn.operands[index]
        if op.type == CS_OP_REG:
            name: str = insn.reg_name(op.reg)  # pyright: ignore[reportAssignmentType]
            return self._reg_read(builder, name)
        if op.type == CS_OP_IMM:
            # TODO: is the sign handled correctly?
            return self.types.int_n(op.size * 8).constant(op.imm)
        if op.type == CS_OP_MEM:
            addr = self._operand_mem(builder, insn, op)
            return self._mem_read(builder, addr, self.types.int_n(op.size * 8))
        assert False, "unreachable"

    def _operand_write(self, builder: Builder, insn: CsInsn, index: int, value: Value):
        op: X86Op = insn.operands[index]
        if op.type == CS_OP_REG:
            name: str = insn.reg_name(op.reg)  # pyright: ignore[reportAssignmentType]
            self._reg_write(builder, name, value)
        elif op.type == CS_OP_IMM:
            raise ValueError("Cannot write to CS_OP_IMM")
        elif op.type == CS_OP_MEM:
            addr = self._operand_mem(builder, insn, op)
            assert value.type.int_width == op.size * 8
            # TODO: narrow the write?
            self._mem_write(builder, addr, value)

    def _lift_flags(
        self,
        builder: Builder,
        insn: CsInsn,
        lhs: Value,
        rhs: Value,
        result: Value,
    ):
        is_zero = builder.icmp(IntPredicate.EQ, result, result.type.constant(0))
        zf = builder.zext(is_zero, self.types.i8)
        self._reg_write(builder, "zf", zf)
        # TODO: other flags are not used in the sample

    def _lift_add(self, builder: Builder, insn: CsInsn):
        dst = self._operand_read(builder, insn, 0)
        src = self._operand_read(builder, insn, 1)
        result = builder.add(dst, src)
        self._operand_write(builder, insn, 0, result)
        self._lift_flags(builder, insn, dst, src, result)

    def _lift_sub(self, builder: Builder, insn: CsInsn):
        dst = self._operand_read(builder, insn, 0)
        src = self._operand_read(builder, insn, 1)
        result = builder.sub(dst, src)
        self._operand_write(builder, insn, 0, result)
        self._lift_flags(builder, insn, dst, src, result)

    def _mem_write(self, builder: Builder, addr: Value, value: Value):
        assert self.function, "call switch first"
        memory = self.function.get_param(0)
        ptr = builder.gep(self.types.i8, memory, [addr])
        builder.store(value, ptr)

    def _mem_read(self, builder: Builder, addr: Value, ty: Type):
        assert self.function, "call switch first"
        memory = self.function.get_param(0)
        ptr = builder.gep(self.types.i8, memory, [addr])
        return builder.load(ty, ptr)

    def _lift_push(self, builder: Builder, insn: CsInsn):
        value = self._operand_read(builder, insn, 0)
        rsp = self._reg_read(builder, "rsp")
        rsp_sub = builder.sub(rsp, self.i64.constant(8))
        self._reg_write(builder, "rsp", rsp_sub)
        self._mem_write(builder, rsp_sub, value)

    def _lift_jmp(self, builder: Builder, insn: CsInsn) -> list[int | str]:
        dest = self._operand_read(builder, insn, 0)
        self._reg_write(builder, "rip", dest)  # advance rip
        op = insn.operands[0]
        if op.type == CS_OP_IMM:
            return [op.imm]
        if op.type == CS_OP_REG:
            name: str = insn.reg_name(op.reg)  # pyright: ignore[reportAssignmentType]
            return [name]
        raise NotImplementedError("memory jump operand")

    def _lift_pushfq(self, builder: Builder, insn: CsInsn):
        zf = self._reg_read(builder, "zf")

        value = builder.shl(builder.zext(zf, self.i64), self.i64.constant(6))
        rsp = self._reg_read(builder, "rsp")
        rsp_sub = builder.sub(rsp, self.i64.constant(8))
        self._reg_write(builder, "rsp", rsp_sub)
        self._mem_write(builder, rsp_sub, value)

    def _lift_mov(self, builder: Builder, insn: CsInsn):
        value = self._operand_read(builder, insn, 1)
        self._operand_write(builder, insn, 0, value)

    def _lift_bytes(self, address: int, code: bytes) -> list[int | str]:
        assert self.function, "You need to call switch_function first!"

        insn = self.cs_disasm(address, code)
        print(hex(address), insn.mnemonic, insn.op_str)

        # Create a new block to lift the instruction
        # TODO: how to handle conditional jumps?
        last_block = self.function.last_basic_block
        insn_block = self.function.append_basic_block(
            f"lifted_{hex(address)}_{insn.mnemonic}"
        )
        with last_block.create_builder() as builder:
            builder.br(insn_block)

        with insn_block.create_builder() as builder:
            self._reg_write(builder, "rip", self.i64.constant(address))
            if insn.id == X86_INS_ADD:
                self._lift_add(builder, insn)
            elif insn.id == X86_INS_PUSH:
                self._lift_push(builder, insn)
            elif insn.id == X86_INS_JMP:
                return self._lift_jmp(builder, insn)
            elif insn.id == X86_INS_PUSHFQ:
                self._lift_pushfq(builder, insn)
            elif insn.id == X86_INS_MOV:
                self._lift_mov(builder, insn)
            elif insn.id == X86_INS_SUB:
                self._lift_sub(builder, insn)
            elif insn.id == X86_INS_NOP:
                pass

            else:
                raise NotImplementedError(
                    f"Instruction not implemented: {insn.mnemonic}"
                )

        return [address + insn.size]

    def lift_va(self, va: int):
        assert va >= self.image_base and va < self.image_base + self.image_size
        code = self.pe.get_data(va - self.image_base, 15)
        return self._lift_bytes(va, code)

    def lift_end(self):
        assert self.function
        with self.function.last_basic_block.create_builder() as builder:
            builder.ret_void()


def main():
    pe = pefile.PE("crackme.exe")
    with Lifter.create(pe) as lifter:
        lifter.switch_function("vm")

        queue: Queue[int | str] = Queue()
        queue.put(0x140017A41)
        visited = set()
        while not queue.empty():
            addr = queue.get()
            if addr in visited:
                continue

            if isinstance(addr, str):
                print("TODO: jmp reg")
                assert queue.empty()
                break

            visited.add(addr)

            successors = lifter.lift_va(addr)
            for successor in successors:
                if successor in visited:
                    continue
                queue.put(successor)

        lifter.lift_end()

        print()
        print(lifter.module)
        lifter.module.verify_or_raise()
    pass


if __name__ == "__main__":
    main()
