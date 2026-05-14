from ..semantics import semantic, Semantics
from llvm import Value, Opcode, IntPredicate

from capstone import (
    CS_OP_MEM,
    CS_OP_IMM,
)


@semantic
def not_(sem: Semantics):
    dst = sem.op_read(0)
    result = sem.ir.not_(dst)
    sem.op_write(0, result)


def write_logical_flags(sem: Semantics, result: Value):
    false = sem.const_n(0, 1)
    sem.flag_write("cf", false)
    sem.flag_write("pf", sem.result_parity_even(result))
    sem.flag_write_undef("af")
    sem.flag_write("zf", sem.result_is_zero(result))
    sem.flag_write("sf", sem.result_sign_bit(result))
    sem.flag_write("of", false)


def logical_binop(sem: Semantics, opcode: Opcode):
    dst = sem.op_read(0)
    src = sem.resize_int(sem.op_read(1), dst.type)
    result = sem.ir.binop(opcode, dst, src)
    sem.op_write(0, result)
    write_logical_flags(sem, result)


@semantic
def and_(sem: Semantics):
    logical_binop(sem, Opcode.And)


@semantic
def xor(sem: Semantics):
    logical_binop(sem, Opcode.Xor)


@semantic
def or_(sem: Semantics):
    logical_binop(sem, Opcode.Or)


@semantic
def xorps(sem: Semantics):
    dst = sem.op_read(0)
    src = sem.resize_int(sem.op_read(1), dst.type)
    sem.op_write(0, sem.ir.xor(dst, src))


@semantic
def test(sem: Semantics):
    lhs = sem.op_read(0)
    rhs = sem.resize_int(sem.op_read(1), lhs.type)
    result = sem.ir.and_(lhs, rhs)
    write_logical_flags(sem, result)


def masked_shift_count(sem: Semantics, value: Value, width: int) -> Value:
    count = sem.resize_int(value, sem.types.int_n(width))
    count_mask = 63 if width == 64 else 31
    return sem.ir.and_(count, count.type.constant(count_mask))


def write_shl_flags(sem: Semantics, lhs: Value, count: Value, result: Value):
    width = lhs.type.int_width
    count_nonzero = sem.ir.icmp(IntPredicate.NE, count, count.type.constant(0))
    count_one = sem.ir.icmp(IntPredicate.EQ, count, count.type.constant(1))
    if width < 32:
        count_in_range = sem.ir.icmp(
            IntPredicate.ULT, count, count.type.constant(width)
        )
    else:
        count_in_range = sem.const_n(1, 1)

    cf_defined = sem.ir.and_(count_nonzero, count_in_range)
    safe_count = sem.ir.select(cf_defined, count, count.type.constant(1))
    cf_shift = sem.ir.sub(count.type.constant(width), safe_count)
    cf = sem.ir.trunc(sem.ir.lshr(lhs, cf_shift), sem.i1)
    if width < 32:
        cf = sem.ir.select(count_in_range, cf, sem.flag_undef("cf"))
    sem.flag_write_if(count_nonzero, "cf", cf)

    of_for_one = sem.ir.xor(sem.result_sign_bit(lhs), sem.result_sign_bit(result))
    of = sem.ir.select(count_one, of_for_one, sem.flag_undef("of"))
    sem.flag_write_if(count_nonzero, "of", of)

    sem.flag_write_if(count_nonzero, "pf", sem.result_parity_even(result))
    sem.flag_write_undef_if(count_nonzero, "af")
    sem.flag_write_if(count_nonzero, "zf", sem.result_is_zero(result))
    sem.flag_write_if(count_nonzero, "sf", sem.result_sign_bit(result))


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
    write_shl_flags(sem, dst, count, result)


def write_shr_flags(sem: Semantics, lhs: Value, count: Value, result: Value):
    width = lhs.type.int_width
    count_nonzero = sem.ir.icmp(IntPredicate.NE, count, count.type.constant(0))
    count_one = sem.ir.icmp(IntPredicate.EQ, count, count.type.constant(1))
    if width < 32:
        count_in_range = sem.ir.icmp(
            IntPredicate.ULT, count, count.type.constant(width)
        )
    else:
        count_in_range = sem.const_n(1, 1)

    cf_defined = sem.ir.and_(count_nonzero, count_in_range)
    safe_count = sem.ir.select(cf_defined, count, count.type.constant(1))
    cf_shift = sem.ir.sub(safe_count, count.type.constant(1))
    cf = sem.ir.trunc(sem.ir.lshr(lhs, cf_shift), sem.i1)
    if width < 32:
        cf = sem.ir.select(count_in_range, cf, sem.flag_undef("cf"))
    sem.flag_write_if(count_nonzero, "cf", cf)

    of = sem.ir.select(count_one, sem.result_sign_bit(lhs), sem.flag_undef("of"))
    sem.flag_write_if(count_nonzero, "of", of)

    sem.flag_write_if(count_nonzero, "pf", sem.result_parity_even(result))
    sem.flag_write_undef_if(count_nonzero, "af")
    sem.flag_write_if(count_nonzero, "zf", sem.result_is_zero(result))
    sem.flag_write_if(count_nonzero, "sf", sem.result_sign_bit(result))


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
    write_shr_flags(sem, dst, count, result)


@semantic
def rol(sem: Semantics):
    dst = sem.op_read(0)
    width = dst.type.int_width
    count = masked_shift_count(sem, sem.op_read(1), width)
    rotate_count = sem.ir.urem(count, count.type.constant(width))
    rotate_nonzero = sem.ir.icmp(
        IntPredicate.NE, rotate_count, rotate_count.type.constant(0)
    )
    safe_count = sem.ir.select(rotate_nonzero, rotate_count, count.type.constant(1))

    left = sem.ir.shl(dst, safe_count)
    right_count = sem.ir.sub(count.type.constant(width), safe_count)
    right = sem.ir.lshr(dst, right_count)
    rotated = sem.ir.or_(left, right)
    result = sem.ir.select(rotate_nonzero, rotated, dst)
    sem.op_write(0, result)

    count_nonzero = sem.ir.icmp(IntPredicate.NE, count, count.type.constant(0))
    cf = sem.ir.trunc(result, sem.i1)
    sem.flag_write_if(count_nonzero, "cf", cf)

    count_one = sem.ir.icmp(IntPredicate.EQ, count, count.type.constant(1))
    of_for_one = sem.ir.xor(sem.result_sign_bit(result), cf)
    of = sem.ir.select(count_one, of_for_one, sem.flag_undef("of"))
    sem.flag_write_if(count_nonzero, "of", of)


def write_sar_flags(sem: Semantics, lhs: Value, count: Value, result: Value):
    width = lhs.type.int_width
    count_nonzero = sem.ir.icmp(IntPredicate.NE, count, count.type.constant(0))
    count_one = sem.ir.icmp(IntPredicate.EQ, count, count.type.constant(1))
    if width < 32:
        count_in_range = sem.ir.icmp(
            IntPredicate.ULT, count, count.type.constant(width)
        )
    else:
        count_in_range = sem.const_n(1, 1)

    cf_defined = sem.ir.and_(count_nonzero, count_in_range)
    safe_count = sem.ir.select(cf_defined, count, count.type.constant(1))
    cf_shift = sem.ir.sub(safe_count, count.type.constant(1))
    shifted_out = sem.ir.trunc(sem.ir.lshr(lhs, cf_shift), sem.i1)
    cf = sem.ir.select(count_in_range, shifted_out, sem.result_sign_bit(lhs))
    sem.flag_write_if(count_nonzero, "cf", cf)

    false = sem.const_n(0, 1)
    of = sem.ir.select(count_one, false, sem.flag_undef("of"))
    sem.flag_write_if(count_nonzero, "of", of)

    sem.flag_write_if(count_nonzero, "pf", sem.result_parity_even(result))
    sem.flag_write_undef_if(count_nonzero, "af")
    sem.flag_write_if(count_nonzero, "zf", sem.result_is_zero(result))
    sem.flag_write_if(count_nonzero, "sf", sem.result_sign_bit(result))


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
    write_sar_flags(sem, dst, count, result)


def bit_test_base_and_mask(sem: Semantics) -> tuple[Value, Value, Value | None]:
    base_op = sem.insn.operands[0]
    bit_op = sem.insn.operands[1]
    width = base_op.size * 8
    ty = sem.types.int_n(width)
    raw_bit = sem.op_read(1)

    if base_op.type == CS_OP_MEM:
        base_addr = sem.op_mem(base_op)
        if bit_op.type == CS_OP_IMM:
            # Immediate memory forms use only the low bits of the immediate;
            # assemblers fold any high bits into the displacement.
            bit = sem.resize_int(raw_bit, sem.i64)
            bit_index = sem.ir.urem(bit, sem.const64(width))
            addr = base_addr
        else:
            # Register memory forms address a bit string.  Negative register
            # offsets select bits before the base, so use signed floor division
            # to compute the containing memory element and a non-negative bit.
            bit = sem.resize_int(raw_bit, sem.i64, sign_extend=True)
            divisor = sem.const64(width)
            quotient = sem.ir.sdiv(bit, divisor)
            remainder = sem.ir.srem(bit, divisor)
            rem_negative = sem.ir.icmp(
                IntPredicate.SLT, remainder, remainder.type.constant(0)
            )
            element_index = sem.ir.select(
                rem_negative, sem.ir.sub(quotient, sem.const64(1)), quotient
            )
            bit_index = sem.ir.select(
                rem_negative, sem.ir.add(remainder, divisor), remainder
            )
            element_offset = sem.ir.mul(element_index, sem.const64(base_op.size))
            addr = sem.ir.add(base_addr, element_offset)
        base = sem.mem_read(addr, ty)
    else:
        addr = None
        base = sem.op_read(0)
        bit = sem.resize_int(raw_bit, sem.i64)
        bit_index = sem.resize_int(bit, base.type)
        bit_index = sem.ir.urem(bit_index, base.type.constant(width))

    bit_index = sem.resize_int(bit_index, ty)
    mask = sem.ir.shl(ty.constant(1), bit_index)
    return base, mask, addr


def write_bit_test_flags(sem: Semantics, base: Value, mask: Value):
    sem.flag_write(
        "cf",
        sem.ir.icmp(IntPredicate.NE, sem.ir.and_(base, mask), base.type.constant(0)),
    )
    sem.flag_write_undef("of")
    sem.flag_write_undef("sf")
    sem.flag_write_undef("af")
    sem.flag_write_undef("pf")


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


@semantic
def bts(sem: Semantics):
    base, mask, addr = bit_test_base_and_mask(sem)
    result = sem.ir.or_(base, mask)
    write_bit_test_flags(sem, base, mask)
    if addr is None:
        sem.op_write(0, result)
    else:
        sem.mem_write(addr, result)
