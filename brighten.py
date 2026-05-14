from striga import Semantics, Successor
from llvm import global_context, Module, Value
from container import RawContainer
from bfs import lift_bfs

CODE = RawContainer(bytes.fromhex("48 C1 EF 03 48 8D 04 7F 48 01 F0 48 05 39 05 00 00 C3"), 0x1000)


with global_context().create_module("blog") as module:
    sem = lift_bfs(module, CODE, 0x1000)

    types = module.context.types

    ram = module.add_global(types.array(types.i8, 0), "RAM")

    i64 = types.i64
    lift2_ty = types.function(i64, [i64, i64])
    lift2 = module.add_function("lift2", lift2_ty)
    entry = lift2.append_basic_block("entry")
    with entry.create_builder() as ir:
        state = ir.alloca(sem.state_ty, "state")
        reg_ptr = lambda name: ir.struct_gep(sem.state_ty, state, sem.reg_indices[name], name)
        ir.store(lift2.get_param(0), reg_ptr("rdi"))
        ir.store(lift2.get_param(1), reg_ptr("rsi"))

        stack = ir.alloca(types.i8, i64.constant(4096), "stack")
        stack_ptr = ir.gep(types.i8, stack, [i64.constant(4096 - 8)])
        ir.store(stack_ptr, reg_ptr("rsp"))

        ir.call(sem.function, [ram, state])
        ir.ret(ir.load(i64, reg_ptr("rax")))
    print(module)
