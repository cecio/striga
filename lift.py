from queue import Queue

from striga import Semantics, Successor
from pefile import PE
from llvm import create_context, Value, Module


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
