import pwndbg
from dbgtools.memory import read_u64
from dbgtools.bits import ror64, rol64


# TODO(ju256): get to consts somewhere
TLS_TO_PTR_MANGLE_COOKIE_OFFSET = 0x30


def tls_ptr_mangling_cookie() -> int:
    tls_base = pwndbg.gdblib.tls.find_address_with_register()
    return read_u64(tls_base + TLS_TO_PTR_MANGLE_COOKIE_OFFSET)

def tls_ptr_demangle(mangled_ptr: int) -> int:
    cookie = tls_ptr_mangling_cookie()
    return ror64(mangled_ptr, 0x11) ^ cookie

def tls_ptr_mangle(ptr: int) -> int:
    cookie = tls_ptr_mangling_cookie()
    return rol64(ptr ^ cookie, 0x11)
