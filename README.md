# striga

Striga is an experimental lifter from x86_64 to LLVM IR written in Python.

## Documentation

- [LLVM IR glossary / cheat sheet for Striga](docs/llvm-cheatsheet.md)

## Requirements

- [uv](https://astral.sh/uv)
- [CMake](https://cmake.org)
- LLVM 21+

## Building

You need LLVM 21 or higher. Before running the first build, allow CMake to find LLVM:

```bash
export LLVM_ROOT=$(brew --prefix llvm)
```

Set up the virtual environment:

```bash
uv sync
```
