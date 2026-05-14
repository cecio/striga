from queue import Queue
from llvm import Module, Value
from striga import Semantics, Successor
from container import Container


def lift_bfs(
    module: Module, container: Container, start: int, *, verbose=True
) -> Semantics:
    sem = Semantics(module, verbose=verbose)
    sem.begin(start)

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
            continue

        if dst in visited:
            continue
        visited.add(dst)

        va = dst.const_zext_value
        code = container.get_data(va, 15)
        successors = sem.lift_bytes(va, code)
        for successor in successors:
            if successor.dst in visited:
                continue
            queue.put(successor)

    sem.module.verify_or_raise()
    return sem
