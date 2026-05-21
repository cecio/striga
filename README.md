# Striga

Striga is an experimental x86-64 to LLVM IR lifter written in Python. It uses the experimental [llvm-nanobind](https://github.com/LLVMParty/llvm-nanobind) project.

## Examples

```sh
uv run python lift.py
uv run python brighten.py
uv run python binaryshield.py
```

- `lift.py` lifts sample PE functions to LLVM IR.
- `brighten.py` demonstrates wrapping and optimizing lifted code.
- `binaryshield.py` lifts BinaryShield VM handlers from `tests/binaryshield.exe`.

