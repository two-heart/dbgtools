import gdb
import pwndbg
import ctypes
import struct
import time
import os
import re
from typing import Optional, Sequence
from dataclasses import dataclass
from subprocess import check_output
from dbgtools.logger import Logger
from dbgtools.gdbapi import execute_commands
from dbgtools.regs import *
from dbgtools.memory import write_pointer


PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXEC = 0x4

MAP_ANON = 0x20
MAP_PRIVATE = 0x2


def is_bit_set(val, bit):
    return val & (1 << bit) != 0


def read_bytes(addr: int, count: int) -> bytes:
    return bytes(pwndbg.gdblib.memory.read(addr, count))


def write_bytes(addr: int, data: str | bytes | bytearray) -> None:
    pwndbg.gdblib.memory.write(addr, data)


def read_byte(addr: int) -> int:
    return read_bytes(addr, 1)[0]


read_u8 = read_byte


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


# EXPERIMENTAL: Might not work for different lib versions
def get_std_vec_elements(addr: int, element_size: int) -> list[int]:
    start = read_u64(addr)
    end = read_u64(addr+8)
    return read_array(start, (end-start) // element_size, element_size)


def read_char_array(addr: int, count: int) -> list[int]:
    return read_array(addr, count, 1)


def read_ushort_array(addr: int, count: int) -> list[int]:
    return read_array(addr, count, 2)


def read_uint_array(addr: int, count: int) -> list[int]:
    return read_array(addr, count, 4)


def read_u64_array(addr: int, count: int) -> list[int]:
    return read_array(addr, count, 8)


def write_array(addr, data_array, element_size):
    element_writers = {1: write_byte,
                       2: write_u16,
                       4: write_u32,
                       8: write_u64}
    if element_size not in [1, 2, 4, 8]:
        raise ValueError("element_size has to be in [1, 2, 4, 8]")

    writer = element_writers[element_size]
    for i, v in enumerate(data_array):
        writer(addr + i * element_size, v)


def write_char_array(addr: int, data_array: Sequence[int]) -> None:
    write_array(addr, data_array, 1)


def write_ushort_array(addr: int, data_array: Sequence[int]):
    write_array(addr, data_array, 2)


def write_uint_array(addr: int, data_array: Sequence[int]):
    write_array(addr, data_array, 4)


def write_ulong_array(addr: int, data_array: Sequence[int]):
    write_array(addr, data_array, 8)


def read_reg_ctype_convert(reg_name, conv_func):
    return conv_func(gdb.parse_and_eval(f"${reg_name}")).value


def read_reg8(reg_name):
    return read_reg_ctype_convert(reg_name, ctypes.c_ulong)


def read_reg4(reg_name):
    return read_reg_ctype_convert(reg_name, ctypes.c_uint)


def read_reg2(reg_name):
    return read_reg_ctype_convert(reg_name, ctypes.c_ushort)


def read_reg1(reg_name):
    return read_reg_ctype_convert(reg_name, ctypes.c_ubyte)


def write_reg_ctype_convert(reg_name, v, conv_func):
    v = conv_func(v).value
    set_reg(reg_name, v)


def write_reg8(reg_name, v):
    write_reg_ctype_convert(reg_name, v, ctypes.c_ulong)


def write_reg4(reg_name, v):
    write_reg_ctype_convert(reg_name, v, ctypes.c_uint)


def write_reg2(reg_name, v):
    write_reg_ctype_convert(reg_name, v, ctypes.c_ushort)


def write_reg1(reg_name, v):
    write_reg_ctype_convert(reg_name, v, ctypes.c_ubyte)


reg_readers = {
    "rax": lambda: read_reg8("rax"),
    "eax": lambda: read_reg4("eax"),
    "rbx": lambda: read_reg8("rbx"),
    "ebx": lambda: read_reg4("ebx"),
    "rcx": lambda: read_reg8("rcx"),
    "ecx": lambda: read_reg4("ecx"),
    "rdx": lambda: read_reg8("rdx"),
    "edx": lambda: read_reg4("edx"),
    "rsi": lambda: read_reg8("rsi"),
    "esi": lambda: read_reg4("esi"),
    "rdi": lambda: read_reg8("rdi"),
    "edi": lambda: read_reg4("edi"),
    "rbp": lambda: read_reg8("rbp"),
    "ebp": lambda: read_reg4("ebp"),
    "rsp": lambda: read_reg8("rsp"),
    "esp": lambda: read_reg4("esp"),
    "r8": lambda: read_reg8("r8"),
    "r9": lambda: read_reg8("r9"),
    "r10": lambda: read_reg8("r10"),
    "r11": lambda: read_reg8("r11"),
    "r12": lambda: read_reg8("r12"),
    "r13": lambda: read_reg8("r13"),
    "r14": lambda: read_reg8("r14"),
    "r15": lambda: read_reg8("r15"),
    "r8d": lambda: read_reg4("r8d"),
    "r9d": lambda: read_reg4("r9d"),
    "r10d": lambda: read_reg4("r10d"),
    "r11d": lambda: read_reg4("r11d"),
    "r12d": lambda: read_reg4("r12d"),
    "r13d": lambda: read_reg4("r13d"),
    "r14d": lambda: read_reg4("r14d"),
    "r15d": lambda: read_reg4("r15d"),
    "rip": lambda: read_reg8("rip"),
    "eip": lambda: read_reg4("eip"),
    "al": lambda: read_reg1("al"),
    "bl": lambda: read_reg1("bl"),
    "cl": lambda: read_reg1("cl"),
    "dl": lambda: read_reg1("dl"),
    "ax": lambda: read_reg2("ax"),
    "bx": lambda: read_reg2("bx"),
    "cx": lambda: read_reg2("cx"),
    "dx": lambda: read_reg2("dx"),
    "eflags": lambda: read_reg8("eflags"),
}

reg_writers = {
    "rax": lambda v: write_reg8("rax", v),
    "eax": lambda v: write_reg4("eax", v),
    "rbx": lambda v: write_reg8("rbx", v),
    "ebx": lambda v: write_reg4("ebx", v),
    "rcx": lambda v: write_reg8("rcx", v),
    "ecx": lambda v: write_reg4("ecx", v),
    "rdx": lambda v: write_reg8("rdx", v),
    "edx": lambda v: write_reg4("edx", v),
    "rsi": lambda v: write_reg8("rsi", v),
    "esi": lambda v: write_reg4("esi", v),
    "rdi": lambda v: write_reg8("rdi", v),
    "edi": lambda v: write_reg4("edi", v),
    "rbp": lambda v: write_reg8("rbp", v),
    "ebp": lambda v: write_reg4("ebp", v),
    "rsp": lambda v: write_reg8("rsp", v),
    "esp": lambda v: write_reg4("esp", v),
    "r8": lambda v: write_reg8("r8", v),
    "r9": lambda v: write_reg8("r9", v),
    "r10": lambda v: write_reg8("r10", v),
    "r11": lambda v: write_reg8("r11", v),
    "r12": lambda v: write_reg8("r12", v),
    "r13": lambda v: write_reg8("r13", v),
    "r14": lambda v: write_reg8("r14", v),
    "r15": lambda v: write_reg8("r15", v),
    "r8d": lambda v: write_reg4("r8d", v),
    "r9d": lambda v: write_reg4("r9d", v),
    "r10d": lambda v: write_reg4("r10d", v),
    "r11d": lambda v: write_reg4("r11d", v),
    "r12d": lambda v: write_reg4("r12d", v),
    "r13d": lambda v: write_reg4("r13d", v),
    "r14d": lambda v: write_reg4("r14d", v),
    "r15d": lambda v: write_reg4("r15d", v),
    "rip": lambda v: write_reg8("rip", v),
    "eip": lambda v: write_reg4("eip", v),
    "al": lambda v: write_reg1("al", v),
    "bl": lambda v: write_reg1("bl", v),
    "cl": lambda v: write_reg1("cl", v),
    "dl": lambda v: write_reg1("dl", v),
    "ax": lambda v: write_reg2("ax", v),
    "bx": lambda v: write_reg2("bx", v),
    "cx": lambda v: write_reg2("cx", v),
    "dx": lambda v: write_reg2("dx", v),
    "eflags": lambda v: write_reg8("eflags", v),
}


def read_reg(reg_name):
    return reg_readers[reg_name]()


def write_reg(reg_name, v):
    return reg_writers[reg_name](v)


def read_string_from_reg_ptr(reg_name):
    str_ptr = read_reg(reg_name)
    s = read_bytestring(str_ptr)
    return str_ptr, s


def write_string_to_reg_ptr(reg_name, s):
    str_ptr = read_reg(reg_name)
    write_string(str_ptr, s, len(s))
    return str_ptr, s

>>>>>>> f0cd4f3 (typing and cleanup)

def set_manual_breakpoint(addr):
    gdb.execute(f"b *{hex(addr)}")


def set_manual_watchpoint(addr):
    gdb.execute(f"watch *{hex(addr)}")

def delete_all_breakpoints():
    gdb.execute("del")

del_bps = delete_all_breakpoints

def gdb_run(args=None):
    if args is not None:
        gdb.execute(f"r {' '.join(args)}")
    else:
        gdb.execute("r")

def patch_string_gdb(addr, string):
    cmd = f"set "+" {char["+str(len(string)+1)+"]}"+ f'{hex(addr)} = "{string}"'
    gdb.execute(cmd)


def sim_call(ret_address):
    registers.rsp -= 8
    gdb.execute("set {long*}$rsp="+f"{hex(ret_address)}", to_string=True)


def get_function_symbol_addr(sym_name):
    return pwndbg.gdblib.symbol.address(sym_name)

def ptr_to_symbol(ptr):
    return pwndbg.gdblib.symbol.get(ptr)

def get_malloc_addr():
    return get_function_symbol_addr("__libc_malloc")


def get_free_addr():
    return get_function_symbol_addr("__libc_free")


def get_mmap_addr():
    return get_function_symbol_addr("mmap")


def get_mprotect_addr():
    return get_function_symbol_addr("mprotect")


def is_program_running():
    # very hacky
    try:
        gdb.execute("x $ax", to_string=True)
        return True
    except gdb.error:
        return False


def wrap_readelf_s(libc_path, sym_name):
    data = check_output(f"readelf -s {libc_path}", shell=True).splitlines()
    data = list(filter(lambda l: sym_name in l.decode(), data))
    p = re.compile(f"\\s{sym_name}@@GLIBC")
    parsed_syms = []
    for d in data:
        off = int(d.split(b": ")[1].split()[0], 16)
        sym_name = d.split(b"@@GLIBC_")[0].split()[-1]
        parsed_syms.append((sym_name, off))
    # print(parsed_syms)
    if len(parsed_syms) == 1:
        return parsed_syms
    for ps_name, ps_addr in parsed_syms:
        if ps_name == sym_name:
            return [(ps_name, ps_addr)]
    return parsed_syms


def exit_handler(event):
    logger = Logger.get_instance()
    if logger.used_log:
        logger.write_log_to_log_file()
        logger.print_log()
    # print(f"Finished in {duration}s")

def get_libc_bin_sh(libc_path):
    data = check_output(f'strings -t x {libc_path} | grep "/bin/sh"', shell=True)
    return int(data.split(b"/bin/sh")[0].strip(), 16)


def get_main_arena_off(libc_path):
    # https://github.com/bash-c/main_arena_offset/blob/master/main_arena
    try:
        __free_hook_off = wrap_readelf_s(libc_path, "__free_hook")[0][1]
        __malloc_hook_off = wrap_readelf_s(libc_path, "__malloc_hook")[0][1]
        __realloc_hook_off = wrap_readelf_s(libc_path, "__realloc_hook")[0][1]
    except IndexError:
        print("Couldn't find in libc. Trying with current libc")
        libc_base = get_libc_base()
        free_hook_sym = get_function_symbol_addr("__free_hook")
        malloc_hook_sym = get_function_symbol_addr("__malloc_hook")
        realloc_hook_sym = get_function_symbol_addr("__realloc_hook")
        if any(map(lambda s: s is None, [libc_base, free_hook_sym, malloc_hook_sym, realloc_hook_sym])):
            return -1
        else:
            __free_hook_off = free_hook_sym - libc_base
            __malloc_hook_off = malloc_hook_sym - libc_base
            __realloc_hook_off = realloc_hook_sym - libc_base

    main_arena_off = (__malloc_hook_off - __realloc_hook_off) * 2 + __malloc_hook_off
    return main_arena_off

def wrap_get_got_addr(symbol_name):
    jmpslots = list(pwndbg.wrappers.readelf.get_jmpslots())
    for line in jmpslots:
        address, info, rtype, value, name = line.split()[:5]

        if symbol_name not in name:
                continue
        return int(address, 16)
    return -1

def wrap_get_plt_addr(symbol_name):
    raise NotImplementedError("parsing .plt(.sec) seems to be to hard for tools???? to lazy to implement the parsing myself now")

def resolve_symbol_address(symbol_name, libc_path=None):
    # we might want to be able to also retrieve library .got/.plt addresses
    # however as this is a very unlikely case we ignore it for now :)
    is_binary_sym = symbol_name.endswith("@got") or symbol_name.endswith("@plt")
    if is_binary_sym:
        if symbol_name.endswith("@got"):
            return wrap_get_got_addr(symbol_name.replace("@got", ""))
        else:
            return wrap_get_plt_addr(symbol_name.replace("@plt", ""))

    else:
        if libc_path is None:
            raise ValueError("No libc path provided for libc symbol!")

        try:
            return wrap_readelf_s(libc_path, symbol_name)[0][1]
        except IndexError:
            return -1


def vmmap():
    return pwndbg.gdblib.vmmap.get()

def get_executable_pages():
    return [p for p in vmmap() if p.execute]

def get_heap_base():
    if pwndbg.heap.current is not None:
        heap_ptrs = []
        for arena in pwndbg.heap.current.arenas:
            for heap in arena.heaps:
                heap_ptrs.append(heap.start)
        if len(heap_ptrs) == 1:
            return heap_ptrs[:1]
        else:
            return heap_ptrs
    else:
        for page in vmmap():
            if "heap" in page.objfile:
                return [page.start]
    return [-1]


def get_first_heap_end_address():
    return pwndbg.gdblib.vmmap.find(get_first_heap_address()).end

def get_first_heap_address():
    heap_addresses = get_heap_base()
    return heap_addresses[0]

def finish_func():
    gdb.execute("finish", to_string=True)

def si():
    gdb.execute("si")

def gdb_continue():
    gdb.execute("c")

c = gdb_continue
r = gdb_run

def set_library_path(path):
    gdb.execute(f"set env LD_LIBRARY_PATH {path}")

def call_function(func_ptr, rdi=None, rsi=None, rdx=None, rcx=None, r8=None, r9=None):
    reg_state = registers.dump()
    if rdi is not None:
        registers.rdi = rdi
    if rsi is not None:
        registers.rsi = rsi
    if rdx is not None:
        registers.rdx = rdx
    if rcx is not None:
        registers.rcx = rcx
    if r8 is not None:
        registers.r8 = r8
    if r9 is not None:
        registers.r9 = r9
    rsp_val = registers.rsp
    rip_val = registers.rip
    registers.rip = func_ptr
    registers.rsp = rsp_val - 0x100
    sim_call(rip_val)
    finish_func()
    ret_val = registers.rax
    registers.restore(reg_state)
    return ret_val

def call_func1(func_ptr, rdi):
    return call_function(func_ptr, rdi=rdi)

def call_func2(func_ptr, rdi, rsi):
    return call_function(func_ptr, rdi=rdi, rsi=rsi)

def call_func3(func_ptr, rdi, rsi, rdx):
    return call_function(func_ptr, rdi=rdi, rsi=rsi, rdx=rdx)

def call_func4(func_ptr, rdi, rsi, rdx, rcx):
    return call_function(func_ptr, rdi=rdi, rsi=rsi, rdx=rdx, rcx=rcx)

def call_func5(func_ptr, rdi, rsi, rdx, rcx, r8):
    return call_function(func_ptr, rdi=rdi, rsi=rsi, rdx=rdx, rcx=rcx, r8=r8)

def call_func6(func_ptr, rdi, rsi, rdx, rcx, r8, r9):
    return call_function(func_ptr, rdi=rdi, rsi=rsi, rdx=rdx, rcx=rcx, r8=r8, r9=r9)


def mprotect(address=0, len=0x1000, prot=PROT_READ|PROT_WRITE|PROT_EXEC):
    mprotect_func_ptr = get_mprotect_addr()
    return call_func3(mprotect_func_ptr, address, len, prot)

def mmap(address=0, length=0x1000, protect=PROT_READ|PROT_WRITE|PROT_EXEC,
         flags=MAP_PRIVATE|MAP_ANON, filedes=0, offset=0):
    mmap_func_ptr = get_mmap_addr()
    return call_func6(mmap_func_ptr, address, length, protect, flags, filedes, offset)

# TODO(liam) change the return types of the following functions to Optional[...]
# and where already did make sure they are used as optionals

# TODO(liam) I belief pwndbg by now support something more stable
# if this is true, use pwndbg implementation instead.
def get_libc_base() -> Optional[int]:
    for page in pwndbg.gdblib.vmmap.get():
        if "libc." in page.objfile:
            return page.start

def get_binary_base() -> Optional[int]:
    for page in pwndbg.gdblib.vmmap.get():
        progspace = gdb.current_progspace()
        if  progspace is not None and progspace.filename in page.objfile:
            return page.start

def get_pie_base() -> Optional[int]:
    return get_binary_base()

def force_load_pie_base() -> Optional[int]:
    execute_commands(["entry"])
    return get_pie_base()

def get_current_libc_path() -> Optional[str]:
    for page in pwndbg.gdblib.vmmap.get():
        if "libc" in page.objfile:
            return page.objfile

# very slow and very shit but who gives a fuck about perf anyways :)
def search_libc_in_dir(start_dir="."):
    results = []
    for root, dirs, files in os.walk(start_dir):
        for f in files:
            if f.endswith("libc.so.6"):
                results.append(root + "/" + f)
    return results

def search_libc64_in_dir(start_dir="."):
    all_libcs = search_libc_in_dir(start_dir)
    return list(filter(lambda lc: "64" in lc, all_libcs))

# 32bit generelly not supported anyways yet
def search_libc32_in_dir(start_dir="."):
    all_libcs = search_libc_in_dir(start_dir)
    return [lc for lc in all_libcs if lc not in search_libc64_in_dir(start_dir)]

def get_system_libc_path():
    results = search_libc64_in_dir("/lib")
    if len(results) >= 1:
        return results[0]
    else:
        return ""


def get_vm_log_breakpoint_template(addresses, handler_ids = None, pie=True, print_handlers=False):
    if handler_ids is None:
        handler_ids = []
    else:
        assert len(handler_ids) == len(addresses)

    def get_func_name(i):
        func_id = handler_ids[i] if len(handler_ids) != 0 else i
        return f"vm_handler_{func_id}"

    for i, addr in enumerate(addresses):
        func_id = handler_ids[i] if len(handler_ids) != 0 else i
        func_name_template = f'def {get_func_name(i)}\n    return "OP{func_id}"\n'
        print(func_name_template)

    print()

    for i, addr in enumerate(addresses):
        if pie:
            bp_template = "LogBreakpoint.create_pie_bp"
        else:
            bp_template = "LogBreakpoint.create_pt_bp"

        print(f"{bp_template}({hex(addr)}, {get_func_name(i)})")



gdb.events.exited.connect(exit_handler)
