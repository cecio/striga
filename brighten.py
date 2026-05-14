from llvm import Linkage, Module, Opcode, Value, global_context

from bfs import lift_bfs
from container import RawContainer

CODE = RawContainer(
    bytes.fromhex("48 C1 EF 03 48 8D 04 7F 48 01 F0 48 05 39 05 00 00 C3"),
    0x1000,
)

OPT_PIPELINE = "default<O3>"


def rewrite_ram_geps(module: Module, ram: Value) -> int:
    """Replace GEPs rooted at @RAM with inttoptr(address)."""
    types = module.context.types
    geps = []

    # Save users first: we mutate/delete them below.
    for user in list(ram.users):
        if not user.is_instruction or user.opcode != Opcode.GetElementPtr:
            raise ValueError(f"unexpected @RAM user: {user}")
        geps.append(user)

    for gep in geps:
        if gep.get_operand(0) != ram:
            raise ValueError(f"unexpected @RAM GEP base: {gep}")

        if gep.num_operands == 2:
            if gep.gep_source_element_type != types.i8:
                raise ValueError(f"expected i8 ptradd-style @RAM GEP: {gep}")
            address = gep.get_operand(1)
        elif gep.num_operands == 3:
            zero = gep.get_operand(1)
            if not zero.is_constant_int or zero.const_zext_value != 0:
                raise ValueError(f"expected zero first @RAM GEP index: {gep}")
            address = gep.get_operand(2)
        else:
            raise ValueError(f"unexpected @RAM GEP shape: {gep}")

        with gep.parent.create_builder() as ir:
            ir.position_before(gep)
            ptr = ir.inttoptr(address, types.ptr)
        gep.replace_all_uses_with(ptr)
        gep.erase_from_parent()

    if not ram.users:
        ram.delete_global()

    module.verify_or_raise()
    return len(geps)


def define_ret_stub(module: Module):
    """Make the modeled return hook removable for this demo wrapper."""
    ret_handler = module.get_function("__striga_ret")
    if ret_handler is not None and ret_handler.is_declaration:
        ret_handler.linkage = Linkage.Internal
        entry = ret_handler.append_basic_block("entry")
        with entry.create_builder() as ir:
            ir.ret_void()


with global_context().create_module("blog") as module:
    sem = lift_bfs(module, CODE, 0x1000, verbose=False)

    types = module.context.types
    i64 = types.i64

    ram = module.add_global(types.array(types.i8, 0), "RAM")

    # Make lifted memory symbolic as @RAM. The wrapper still has to pass a value
    # for the ABI, but the parameter is unused after this replacement.
    sem.function.get_param(0).replace_all_uses_with(ram)

    lift2_ty = types.function(i64, [i64, i64])
    lift2 = module.add_function("lift2", lift2_ty)
    entry = lift2.append_basic_block("entry")
    with entry.create_builder() as ir:
        state = ir.alloca(sem.state_ty, "state")

        def reg_ptr(name: str) -> Value:
            return ir.struct_gep(sem.state_ty, state, sem.reg_indices[name], name)

        ir.store(lift2.get_param(0), reg_ptr("rdi"))
        ir.store(lift2.get_param(1), reg_ptr("rsi"))

        stack = ir.alloca(types.i8, i64.constant(4096), "stack")
        stack_ptr = ir.gep(types.i8, stack, [i64.constant(4096 - 8)])
        retaddr_store = ir.store(i64.constant(0), stack_ptr)
        retaddr_store.inst_alignment = 1
        ir.store(ir.ptrtoint(stack_ptr, i64), reg_ptr("rsp"))

        ir.call(sem.function, [types.ptr.undef(), state])
        ir.ret(ir.load(i64, reg_ptr("rax")))

    module.verify_or_raise()

    # 1. Inline/optimize with @RAM assigned to the lifted memory parameter.
    module.optimize(OPT_PIPELINE)

    # 2. Brighten lifted memory: @RAM + integer address -> inttoptr(address).
    rewrite_ram_geps(module, ram)

    # 3. Now that RAM accesses have been brightened, discard the modeled ret
    #    hook for this demo and let LLVM clean up the remaining wrapper noise.
    #    Undefined flag helpers are already declared memory(none) by Semantics,
    #    so their dead uses fold away without local stub definitions.
    define_ret_stub(module)
    module.verify_or_raise()
    module.optimize(OPT_PIPELINE)

    print(module)
