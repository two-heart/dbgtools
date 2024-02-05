import pwndbg
import struct
from typing import Optional, Sequence
from dbgtools.regs import registers


def read_bytes(addr: int, count: int) -> bytes:
    return bytes(pwndbg.gdblib.memory.read(addr, count))


def write_bytes(addr: int, data: str | bytes | bytearray) -> None:
    pwndbg.gdblib.memory.write(addr, data)


def read_byte(addr: int) -> int:
    return read_bytes(addr, 1)[0]


read_u8 = read_byte
read_char = read_byte


def write_byte(addr: int, b: int) -> None:
    write_bytes(addr, bytes([b]))


write_u8 = write_byte


def read_u64(addr: int) -> int:
    m = read_bytes(addr, 8)
    return struct.unpack("<Q", m)[0]


def write_u64(addr: int, l: int) -> None:
    write_bytes(addr, struct.pack("<Q", l))


def read_u16(addr: int) -> int:
    m = read_bytes(addr, 2)
    return struct.unpack("<H", m)[0]


def write_u16(addr: int, u: int) -> None:
    write_bytes(addr, struct.pack("<H", u))


def read_u32(addr: int) -> int:
    m = read_bytes(addr, 4)
    return struct.unpack("<I", m)[0]


def write_u32(addr:int, u: int) -> None:
    write_bytes(addr, struct.pack("<I", u))


def read_s64(addr: int) -> None:
    m = read_bytes(addr, 8)
    return struct.unpack("<q", m)[0]


def write_s64(addr: int, l: int) -> None:
    write_bytes(addr, struct.pack("<q", l))


def read_double(addr: int) -> float:
    m = read_bytes(addr, 8)
    return struct.unpack("<d", m)[0]


def write_double(addr: int, v) -> None:
    write_bytes(addr, struct.pack("<d", v))


def write_float(addr: int, v) -> None:
    write_bytes(addr, struct.pack("<f", v))


def read_float(addr: int) -> float:
    m = read_bytes(addr, 4)
    return struct.unpack("<f", m)[0]


def read_s32(addr: int) -> int:
    m = read_bytes(addr, 4)
    return struct.unpack("<i", m)[0]


def write_s32(addr: int, i: int) -> None:
    write_bytes(addr, struct.pack("<i", i))


def read_pointer(addr: int, deref_count:int = 0) -> int:
    if deref_count >= 1:
        return read_pointer(read_pointer(addr), deref_count=deref_count-1)
    else:
        return read_u64(addr)

def read_stack(off: int = 0):
    rsp_val = registers.rsp
    return read_u64(rsp_val + off * 8)

def write_pointer(addr: int, ptr: int) -> None:
    write_u64(addr, ptr)

def read_bool(addr: int) -> bool:
    v = read_u32(addr)
    return True if v != 0 else False

def write_bool(addr: int, v: bool) -> None:
    write_u32(addr, 1 if v else 0)


def read_bytestring(addr: int, length: Optional[int] = None) -> bytes:
     s = b""
     b = read_byte(addr)
     i = 1
     s += bytes([b])
     while b != 0x0 and (length is None or i < length):
         b = read_byte(addr + i)
         s += bytes([b])
         i += 1
     return s

read_string = read_bytestring

def write_string(addr: int, s: bytes, length: Optional[int] = None,
                 append_zero: bool = False):

    # extend string to length with null bytes or crop it
    if length is not None:
        s = s[:length]
        if len(s) < length:
            s += bytes([0]) * (length - len(s))

    if append_zero and s[-1] != 0:
        s += bytes([0])

    write_bytes(addr, s)


def read_array(addr: int, count: int, element_size: int) -> list[int]:
    element_readers = {1: read_byte, 2: read_u16, 4: read_u32, 8: read_u64}
    if element_size not in [1, 2, 4, 8]:
        raise ValueError("element_size has to be in [1, 2, 4, 8]")

    reader = element_readers[element_size]
    arr = []
    for i in range(count):
        arr.append(reader(addr + i * element_size))
    return arr


def read_u8_array(addr: int, count: int) -> Sequence[int]:
    return read_array(addr, count, 1)

read_char_array = read_u8_array

def read_u16_array(addr: int, count: int) -> Sequence[int]:
    return read_array(addr, count, 2)


def read_u32_array(addr: int, count: int) -> Sequence[int]:
    return read_array(addr, count, 4)


def read_u64_array(addr: int, count: int) -> Sequence[int]:
    return read_array(addr, count, 8)


def write_array(addr: int, data_array: Sequence[int], element_size: int):
    element_writers = {1: write_byte,
                       2: write_u16,
                       4: write_u32,
                       8: write_u64}
    if element_size not in [1, 2, 4, 8]:
        raise ValueError("element_size has to be in [1, 2, 4, 8]")

    writer = element_writers[element_size]
    for i, v in enumerate(data_array):
        writer(addr + i * element_size, v)


def write_u8_array(addr: int, data_array: Sequence[int]):
    write_array(addr, data_array, 1)

write_char_array = write_u8_array

def write_u16_array(addr: int, data_array: Sequence[int]):
    write_array(addr, data_array, 2)


def write_u32_array(addr: int, data_array: Sequence[int]):
    write_array(addr, data_array, 4)

def write_u64_array(addr: int, data_array: Sequence[int]):
    write_array(addr, data_array, 8)


def read_string_from_reg_ptr(reg_name):
    str_ptr = read_reg(reg_name)
    s = read_bytestring(str_ptr)
    return str_ptr, s

def write_string_to_reg_ptr(reg_name, s):
    str_ptr = read_reg(reg_name)
    write_string(str_ptr, s, len(s))
    return str_ptr, s
