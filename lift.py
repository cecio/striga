from contextlib import contextmanager

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

import llvm


class Lifter:
    def __init__(self, module: llvm.Module):
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True
        self.module = module
        self.context = module.context
        types = self.context.types
        self.types = types

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
            "r8": 64,
            "r10": 64,
            "r11": 64,
            "r12": 64,
            "r13": 64,
            "r14": 64,
            "r15": 64,
            "rip": 64,
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
        self.reg_ptrs: dict[str, llvm.Value] = {}
        self.state_ty = types.struct(self.reg_types.values(), name="State")
        self.function: llvm.Function | None = None
        self.lifted_ty = types.function(types.void, [types.ptr, types.ptr])

    @staticmethod
    @contextmanager
    def create(module_name="lifted"):
        with llvm.create_context() as context:
            with context.create_module(module_name) as module:
                yield Lifter(module)

    def cs_disasm(self, address: int, code: bytes) -> CsInsn:
        for insn in self.cs.disasm(code, address, count=1):  # ty: ignore[missing-argument, invalid-argument-type]
            return insn
        raise ValueError(f"Failed to disassemble {code.hex()}@{hex(address)}")

    def switch_function(self, name: str):
        fn = self.module.get_function(name)
        if fn is None:
            fn = self.module.add_function(name, self.lifted_ty)
            fn.linkage = llvm.Linkage.Internal
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
                    insn.opcode == llvm.Opcode.GetElementPtr
                    and insn.gep_source_element_type == self.state_ty
                ):
                    assert insn.name in self.reg_types, "unexpected GEP"
                self.reg_ptrs[insn.name] = insn

        self.function = fn

    def _reg_read(self, builder: llvm.Builder, name: str):
        reg_ptr = self.reg_ptrs[name]
        return builder.load(self.reg_types[name], reg_ptr)

    def _reg_write(self, builder: llvm.Builder, name: str, value: llvm.Value):
        reg_ptr = self.reg_ptrs[name]
        # TODO: zero extend/cast?
        builder.store(value, reg_ptr)

    def _operand_read(
        self, builder: llvm.Builder, insn: CsInsn, index: int
    ) -> llvm.Value:
        op: X86Op = insn.operands[index]
        if op.type == CS_OP_REG:
            name: str = insn.reg_name(op.reg)  # pyright: ignore[reportAssignmentType]
            return self._reg_read(builder, name)
        if op.type == CS_OP_IMM:
            # TODO: is the sign handled correctly?
            return self.types.int_n(op.size * 8).constant(op.imm)
        if op.type == CS_OP_MEM:
            raise NotImplementedError("CS_OP_MEM")
        assert False, "unreachable"

    def _operand_write(
        self, builder: llvm.Builder, insn: CsInsn, index: int, value: llvm.Value
    ):
        op: X86Op = insn.operands[index]
        if op.type == CS_OP_REG:
            name: str = insn.reg_name(op.reg)  # pyright: ignore[reportAssignmentType]
            self._reg_write(builder, name, value)
        elif op.type == CS_OP_IMM:
            raise ValueError("Cannot write to CS_OP_IMM")
        elif op.type == CS_OP_MEM:
            raise NotImplementedError("CS_OP_MEM")

    def _lift_add(self, builder: llvm.Builder, insn: CsInsn):
        op2 = self._operand_read(builder, insn, 1)
        op1 = self._operand_read(builder, insn, 0)
        result = builder.add(op1, op2)
        self._operand_write(builder, insn, 0, result)
        # TODO: flags

    def _mem_write(self, builder: llvm.Builder, addr: llvm.Value, value: llvm.Value):
        assert self.function, "call switch first"
        memory = self.function.get_param(0)
        ptr = builder.gep(self.types.i8, memory, [addr])
        builder.store(value, ptr)

    def _lift_push(self, builder: llvm.Builder, insn: CsInsn):
        value = self._operand_read(builder, insn, 0)
        rsp = self._reg_read(builder, "rsp")
        rsp_sub = builder.sub(rsp, self.types.i64.constant(8))
        self._reg_write(builder, "rsp", rsp_sub)
        self._mem_write(builder, rsp_sub, value)

    def lift_insn(self, address: int, code: bytes):
        assert self.function, f"You need to call switch_function first!"

        # Create a new block to lift the instruction
        # TODO: how to handle conditional jumps?
        last_block = self.function.last_basic_block
        insn_block = self.function.append_basic_block(f"lifted_{hex(address)}")
        with last_block.create_builder() as builder:
            builder.br(insn_block)

        insn = self.cs_disasm(address, code)
        print(insn.mnemonic, insn.op_str)

        with insn_block.create_builder() as builder:
            self._reg_write(builder, "rip", self.types.i64.constant(address))
            if insn.id == X86_INS_ADD:
                self._lift_add(builder, insn)
            elif insn.id == X86_INS_PUSH:
                self._lift_push(builder, insn)
            else:
                raise NotImplementedError(
                    f"Instruction not implemented: {insn.mnemonic}"
                )
        print(insn_block)

    def lift_end(self):
        assert self.function
        with self.function.last_basic_block.create_builder() as builder:
            builder.ret_void()


def main():
    with Lifter.create() as lifter:
        lifter.switch_function("handler1")
        lifter.switch_function("handler1")
        lifter.lift_insn(0x14001603E, bytes.fromhex("4D 01 F5"))
        lifter.lift_insn(0x140017A41, bytes.fromhex("68 8F 67 01 00"))

        lifter.lift_end()

        lifter.module.verify_or_raise()
        print(lifter.module)
    pass


if __name__ == "__main__":
    main()
