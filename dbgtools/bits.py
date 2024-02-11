def rol(val: int, r_bits: int, max_bits: int) -> int:
    return (val << r_bits % max_bits) & (2**max_bits - 1) | \
    ((val & (2**max_bits - 1)) >> (max_bits - (r_bits % max_bits)))

def ror(val: int, r_bits: int, max_bits: int) -> int: \
    return ((val & (2**max_bits - 1)) >> r_bits % max_bits) | \
    (val << (max_bits - (r_bits % max_bits)) & (2**max_bits - 1))

def rol64(val: int, r_bits: int):
    return rol(val, r_bits, 64)

def ror64(val: int, r_bits: int):
    return ror(val, r_bits, 64)
