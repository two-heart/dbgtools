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
from dbgtools.gdbapi import execute_command
from dbgtools.regs import *
from dbgtools.memory import write_pointer


def is_program_running():
    # very hacky
    try:
        registers.ax
        return True
    except gdb.error:
        return False


def patch_string_gdb(addr, string):
    cmd = f"set "+" {char["+str(len(string)+1)+"]}"+ f'{hex(addr)} = "{string}"'
    gdb.execute(cmd)


def get_function_symbol_addr(sym_name):
    return pwndbg.gdblib.symbol.address(sym_name)

def ptr_to_symbol(ptr):
    return pwndbg.gdblib.symbol.get(ptr)


# FIXME(ju256): do better here
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
    logger = Logger()
    if logger.used_log:
        logger.write_log_to_log_file()
        logger.print_log()
    # print(f"Finished in {duration}s")

def get_libc_bin_sh(libc_path):
    data = check_output(f'strings -t x {libc_path} | grep "/bin/sh"', shell=True)
    return int(data.split(b"/bin/sh")[0].strip(), 16)


# TODO(ju256): just using current libc in case of failure is confusing. fix
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

# FIXME(ju256): fully bricked
def wrap_get_got_addr(symbol_name):
    jmpslots = list(pwndbg.wrappers.readelf.get_jmpslots())
    for line in jmpslots:
        address, info, rtype, value, name = line.split()[:5]

        if symbol_name not in name:
                continue
        return int(address, 16)
    return -1

def wrap_get_plt_addr(symbol_name):
    # FIXME: implement
    raise NotImplementedError("parsing .plt(.sec) seems to be to hard for tools???? to lazy to implement the parsing myself now")

def resolve_symbol_address(symbol_name, libc_path=None):
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

def set_library_path(path):
    gdb.execute(f"set env LD_LIBRARY_PATH {path}")


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
    execute_command("entry")
    return get_pie_base()

def get_current_libc_path() -> Optional[str]:
    for page in pwndbg.gdblib.vmmap.get():
        if "libc" in page.objfile:
            return page.objfile


gdb.events.exited.connect(exit_handler)
