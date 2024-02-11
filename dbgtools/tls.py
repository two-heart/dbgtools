import pwndbg
from dbgtools.memory import read_u64
from dbgtools.bits import ror64, rol64
from dbgtools.types import Struct, StructField, U64Type


# TODO(ju256): get to consts somewhere
TLS_TO_CANARY_OFFSET = 0x28


# TODO(ju256): expand on this
class TLS(Struct):
    canary: StructField[TLS_TO_CANARY_OFFSET, U64Type]
    ptr_mangle_cookie: U64Type


def base() -> int:
    return pwndbg.gdblib.tls.find_address_with_register()

def tls() -> TLS:
    return TLS(base())

def ptr_mangling_cookie() -> int:
    return tls().ptr_mangling_cookie

def ptr_demangle(mangled_ptr: int) -> int:
    cookie = ptr_mangling_cookie()
    return ror64(mangled_ptr, 0x11) ^ cookie

def ptr_mangle(ptr: int) -> int:
    cookie = ptr_mangling_cookie()
    return rol64(ptr ^ cookie, 0x11)

def canary() -> int:
    return tls().canary
