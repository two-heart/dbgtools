from dbgtools.regs import *
from dbgtools.gdbapi import execute_commands


PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXEC = 0x4

MAP_ANON = 0x20
MAP_PRIVATE = 0x2


def get_malloc_addr():
    return get_function_symbol_addr("__libc_malloc")

def get_free_addr():
    return get_function_symbol_addr("__libc_free")

def get_mmap_addr():
    return get_function_symbol_addr("mmap")

def get_mprotect_addr():
    return get_function_symbol_addr("mprotect")


def sim_call(ret_address: int):
    registers.rsp -= 8
    execute_commands(["set {long*}$rsp="+f"{hex(ret_address)}"])

def finish_func():
    execute_commands(["finish"])

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

def mmap(address=0, size=0x1000, protect=PROT_READ|PROT_WRITE|PROT_EXEC,
         flags=MAP_PRIVATE|MAP_ANON, filedes=0, offset=0):
    mmap_func_ptr = get_mmap_addr()
    return call_func6(mmap_func_ptr, address, size, protect, flags, filedes, offset)
