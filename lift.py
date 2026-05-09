from queue import Queue

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
)


_semantics = {}


def semantic(fn):
    _semantics[fn.__name__.removesuffix("_")] = fn
    return fn


class Semantics:
    def __init__(self, module: Module):
        self.module = module

        # Disassembler
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True

        # Aliases
        self.context = module.context
        types = self.context.types
        self.types = self.context.types
        self.i64 = types.i64

        # Register state
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
        self.extend_regs = {
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
        self.reg_types = {
            name: types.int_n(size) for name, size in self.reg_sizes.items()
        }
        self.state_ty = types.struct(self.reg_types.values(), name="State")
        self.lifted_ty = types.function(types.void, [types.ptr, types.ptr])

        # Set per function lifting
        self.function: Function
        self.reg_ptrs: dict[str, Value] = {}

        # Set per instruction
        self.ir: Builder
        self.insn: CsInsn

    def begin(self, name: str):
        fn = self.module.get_function(name)
        if fn is None:
            fn = self.module.add_function(name, self.lifted_ty)
            fn.linkage = Linkage.Internal
            memory, state = fn.params
            memory.name = "memory"
            state.name = "state"

            entry = fn.append_basic_block("initialize")
            assert fn.last_basic_block == entry
            with entry.create_builder() as ir:
                for i, name in enumerate(self.reg_sizes.keys()):
                    reg_ptr = ir.struct_gep(self.state_ty, state, i, name)
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

    def end(self):
        with self.function.last_basic_block.create_builder() as ir:
            ir.ret_void()

    def cs_disasm(self, address: int, code: bytes) -> CsInsn:
        for insn in self.cs.disasm(code, address, count=1):  # ty: ignore[missing-argument, invalid-argument-type]
            return insn
        raise ValueError(f"Failed to disassemble {code.hex()}@{hex(address)}")

    def lift_bytes(self, address: int, code: bytes) -> list[int | str]:
        assert getattr(self, "function", None), (
            "You need to call switch_function first!"
        )

        insn = self.cs_disasm(address, code)
        print(hex(address), insn.mnemonic, insn.op_str)

        # Create a new block to lift the instruction
        # TODO: how to handle conditional jumps?
        last_block = self.function.last_basic_block
        insn_block = self.function.append_basic_block(
            f"lifted_{hex(address)}_{insn.mnemonic}"
        )
        with last_block.create_builder() as ir:
            ir.br(insn_block)

        with insn_block.create_builder() as ir:
            self.ir = ir
            self.insn = insn
            self.reg_write("rip", self.i64.constant(address))
            handler = _semantics.get(insn.id)
            if not handler:
                raise NotImplementedError(insn.mnemonic)

            successors = handler(self)
            return successors if successors else [address + insn.size]

    def reg_name(self, reg_id: int) -> str:
        return self.insn.reg_name(reg_id)  # pyright: ignore[reportReturnType]

    def reg_read(self, name: str):
        reg_ptr = self.reg_ptrs[name]
        return self.ir.load(self.reg_types[name], reg_ptr)

    def reg_write(self, name: str, value: Value):
        extend_reg = self.extend_regs.get(name)
        if extend_reg:
            reg_ptr = self.reg_ptrs[extend_reg]
            assert value.type.int_width == 32
            self.ir.store(self.ir.zext(value, self.i64), reg_ptr)
        else:
            reg_ptr = self.reg_ptrs[name]
            assert value.type.int_width == self.reg_sizes[name]
            self.ir.store(value, reg_ptr)

    def operand_mem(self, op: X86Op) -> Value:
        assert op.type == CS_OP_MEM

        ir = self.ir
        i64 = self.i64
        addr = i64.constant(op.mem.disp)

        base = op.mem.base
        if base != X86_REG_INVALID:
            if base == X86_REG_RIP:
                addr = ir.add(addr, i64.constant(self.insn.address + self.insn.size))
            else:
                base_name: str = self.reg_name(base)  # pyright: ignore[reportAssignmentType]
                base_value = self.reg_read(base_name)
                addr = ir.add(addr, base_value)

        index = op.mem.index
        if index != X86_REG_INVALID:
            index_name: str = self.reg_name(index)  # pyright: ignore[reportAssignmentType]
            index_value = self.reg_read(index_name)
            scale_value = i64.constant(op.mem.scale)
            addr = ir.add(addr, ir.mul(index_value, scale_value))

        if op.mem.segment == X86_REG_GS:
            addr = ir.add(addr, self.reg_read("gsbase"))

        return addr

    def operand_read(self, index: int) -> Value:
        op: X86Op = self.insn.operands[index]
        if op.type == CS_OP_REG:
            name = self.reg_name(op.reg)  # pyright: ignore[reportAssignmentType]
            return self.reg_read(name)
        if op.type == CS_OP_IMM:
            # TODO: is the sign handled correctly?
            return self.types.int_n(op.size * 8).constant(op.imm)
        if op.type == CS_OP_MEM:
            addr = self.operand_mem(op)
            return self.mem_read(addr, self.types.int_n(op.size * 8))
        assert False, "unreachable"

    def operand_write(self, index: int, value: Value):
        op: X86Op = self.insn.operands[index]
        if op.type == CS_OP_REG:
            name = self.reg_name(op.reg)  # pyright: ignore[reportAssignmentType]
            self.reg_write(name, value)
        elif op.type == CS_OP_IMM:
            raise ValueError("Cannot write to CS_OP_IMM")
        elif op.type == CS_OP_MEM:
            addr = self.operand_mem(op)
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


@semantic
def add(sem: Semantics):
    dst = sem.operand_read(0)
    src = sem.operand_read(1)
    result = sem.ir.add(dst, src)
    sem.operand_write(0, result)
    sem.lift_flags(dst, src, result)


@semantic
def sub(sem: Semantics):
    dst = sem.operand_read(0)
    src = sem.operand_read(1)
    result = sem.ir.sub(dst, src)
    sem.operand_write(0, result)
    sem.lift_flags(dst, src, result)


@semantic
def push(sem: Semantics):
    value = sem.operand_read(0)
    rsp = sem.reg_read("rsp")
    rsp_sub = sem.ir.sub(rsp, sem.i64.constant(8))
    sem.reg_write("rsp", rsp_sub)
    sem.mem_write(rsp_sub, value)


@semantic
def jmp(sem: Semantics) -> list[int | str]:
    dst = sem.operand_read(0)
    sem.reg_write("rip", dst)  # advance rip
    op = sem.insn.operands[0]
    if op.type == CS_OP_IMM:
        return [op.imm]
    if op.type == CS_OP_REG:
        name: str = sem.insn.reg_name(op.reg)  # pyright: ignore[reportAssignmentType]
        return [name]
    raise NotImplementedError("memory jump operand")


@semantic
def pushfq(sem: Semantics):
    ir = sem.ir
    zf = sem.reg_read("zf")
    value = ir.shl(ir.zext(zf, sem.i64), sem.i64.constant(6))
    rsp = sem.reg_read("rsp")
    rsp_sub = ir.sub(rsp, sem.i64.constant(8))
    sem.reg_write("rsp", rsp_sub)
    sem.mem_write(rsp_sub, value)


@semantic
def mov(sem: Semantics):
    value = sem.operand_read(1)
    sem.operand_write(0, value)


def lift(module: Module, pe: PE, start: int):
    image_base = pe.OPTIONAL_HEADER.ImageBase  # pyright: ignore[reportOptionalMemberAccess, reportAttributeAccessIssue]
    image_size = pe.OPTIONAL_HEADER.SizeOfImage  # pyright: ignore[reportOptionalMemberAccess, reportAttributeAccessIssue]
    sem = Semantics(module)
    sem.begin(f"lifted_{hex(start)}")

    queue: Queue[int | str] = Queue()
    queue.put(start)
    visited = set()
    while not queue.empty():
        va = queue.get()
        if va in visited:
            continue

        if isinstance(va, str):
            print("TODO: jmp reg")
            assert queue.empty()
            break

        visited.add(va)

        assert va >= image_base and va < image_base + image_size
        code = pe.get_data(va - image_base, 15)
        successors = sem.lift_bytes(va, code)
        for successor in successors:
            if successor in visited:
                continue
            queue.put(successor)

    sem.end()
    print(sem.module)
    sem.module.verify_or_raise()


if __name__ == "__main__":
    with create_context() as context:
        with context.create_module("binaryshield") as module:
            lift(module, PE("crackme.exe"), 0x140017A41)
