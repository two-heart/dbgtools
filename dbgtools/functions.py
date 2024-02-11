from typing import Optional, Type
from abc import ABC, abstractmethod
from dbgtools.regs import *
from dbgtools.gdbapi import execute_command, finish, si
from dbgtools.main import get_function_symbol_addr, find_gadget
from dbgtools.regs import RegisterDescriptor, registers
from dbgtools.memory import write_bytes
import pwn


# TODO(ju256): move/get constants to/from somewhere
PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXEC = 0x4

MAP_ANON = 0x20
MAP_PRIVATE = 0x2

SYS_READ = 0x0
SYS_WRITE = 0x1
SYS_EXIT = 0x3c


class RegTransparentScope:
    def __init__(self):
        self._reg_state: Optional[dict[str, RegisterDescriptor]] = None

    def __enter__(self):
        self._reg_state = registers.dump()

    def __exit__(self, exc_type, exc_val, exc_tb):
        registers.restore(self._reg_state)


class CallingConvention(ABC):
    def __init__(self, *args):
        self._arglist = args

    @abstractmethod
    def call(self, ptr: int):
        ...

    def callsym(self, sym: str):
        ptr = get_function_symbol_addr(sym)
        return self.call(ptr)

    def arg(self, idx: int) -> int:
        return self._arglist[idx] if len(self._arglist) > idx else None

    def argcount(self) -> int:
        return len(self._arglist)



class SystemVAMD64(CallingConvention):
    def call(self, func_ptr: int):
        # TODO(ju256): allow stack arguments
        if self.argcount() > 6:
            raise ValueError("Currently only <= 6 arguments are supported")

        rdi = self.arg(0)
        rsi = self.arg(1)
        rdx = self.arg(2)
        rcx = self.arg(3)
        r8 = self.arg(4)
        r9 = self.arg(5)

        with RegTransparentScope():
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

            rip_val = registers.rip
            registers.rip = func_ptr
            sim_call(rip_val)
            finish()
            return registers.rax


class Syscall64(CallingConvention):
    def call(self, syscall_gadget_ptr: int):
        if self.argcount() == 0:
            raise ValueError("Syscall number has to be specified as first argument")

        rax = self.arg(0)
        assert rax is not None

        rdi = self.arg(1)
        rsi = self.arg(2)
        rdx = self.arg(3)
        r10 = self.arg(4)
        r8 = self.arg(5)
        r9 = self.arg(6)

        with RegTransparentScope():
            registers.rax = rax
            if rdi is not None:
                registers.rdi = rdi
            if rsi is not None:
                registers.rsi = rsi
            if rdx is not None:
                registers.rdx = rdx
            if r10 is not None:
                registers.r10 = r10
            if r8 is not None:
                registers.r8 = r8
            if r9 is not None:
                registers.r9 = r9

            rip_val = registers.rip
            registers.rip = syscall_gadget_ptr
            si() # execute syscall
            return registers.rax


def get_malloc_addr():
    return get_function_symbol_addr("__libc_malloc")

def get_free_addr():
    return get_function_symbol_addr("__libc_free")

def get_mmap_addr():
    return get_function_symbol_addr("mmap")

def get_mprotect_addr():
    return get_function_symbol_addr("mprotect")

def get_puts_addr():
    return get_function_symbol_addr("puts")

def sim_call(ret_address: int):
    registers.rsp -= 8
    execute_command("set {long*}$rsp="+f"{hex(ret_address)}")


def mprotect(address: int = 0, len: int = 0x1000, prot: int = PROT_READ|PROT_WRITE|PROT_EXEC, calling_convention: Type[CallingConvention] = SystemVAMD64):
    return calling_convention(address, len, prot).callsym("mprotect")

def mmap(address: int = 0, size: int = 0x1000, protect: int = PROT_READ|PROT_WRITE|PROT_EXEC,
         flags: int = MAP_PRIVATE|MAP_ANON, filedes: int = 0, offset: int = 0, calling_convention: Type[CallingConvention] = SystemVAMD64):
    return calling_convention(address, size, protect, flags, filedes, offset).callsym("mmap")

def malloc(size: int, calling_convention: Type[CallingConvention] = SystemVAMD64):
    return calling_convention(size).callsym("malloc")

def free(ptr: int, calling_convention: Type[CallingConvention] = SystemVAMD64):
    return calling_convention(ptr).callsym("free")

def puts(ptr: int, calling_convention: Type[CallingConvention] = SystemVAMD64):
    return calling_convention(ptr).callsym("puts")

def munmap(addr: int, length: int, calling_convention: Type[CallingConvention] = SystemVAMD64):
    return calling_convention(addr, length).callsym("munmap")

def syscall(num: int, *args):
    syscall_gadget_bytes = pwn.asm("syscall", arch="amd64", os="linux")
    tmp_page = None
    try:
        page, offset = next(find_gadget(syscall_gadget_bytes))
        syscall_gadget_ptr = page.start + offset
    except StopIteration:
        tmp_page = mmap(size=0x1000)
        write_bytes(tmp_page, syscall_gadget_bytes)
        syscall_gadget_ptr = tmp_page

    ret_value = Syscall64(num, *args).call(syscall_gadget_ptr)
    if tmp_page is not None:
        munmap(tmp_page, 0x1000)
    return ret_value

def sys_read(fd: int, buf: int, n: int):
    return syscall(SYS_READ, fd, buf, n)

def sys_write(fd: int, buf: int, n: int):
    return syscall(SYS_WRITE, fd, buf, n)

def sys_exit(error_code: int):
    return syscall(SYS_EXIT, error_code)
