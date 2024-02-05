import gdb
import ctypes
from dataclasses import dataclass


def is_bit_set(val, bit):
    return val & (1 << bit) != 0


def read_reg_ctype_convert(reg_name, conv_func):
    return conv_func(gdb.parse_and_eval(f"${reg_name}")).value

def set_reg(reg_name, val):
    gdb.execute(f"set ${reg_name} = {hex(val)}", to_string=True)


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


class RegisterDescriptor:
    def __init__(self, reg_name: str):
        self._reg_name = reg_name

    def __get__(self, obj, objtype=None):
        return read_reg(self._reg_name)

    def __set__(self, obj, value):
        return write_reg(self._reg_name, value)

    def info(self):
        return ""


def get_eflags_info():
    return EFLAGSRegisterDescriptor("eflags").info()


class EFLAGSRegisterDescriptor(RegisterDescriptor):
    def __init__(self, reg_name: str):
        super().__init__(reg_name)

    def _check_flag_bit(self, bit):
        return is_bit_set(self.__get__(None), bit)

    def info(self):
        val = self.__get__(None)
        infol = []

        CF = self._check_flag_bit(0)
        PF = self._check_flag_bit(2)
        AF = self._check_flag_bit(4)
        ZF = self._check_flag_bit(6)
        SF = self._check_flag_bit(7)
        TF = self._check_flag_bit(8)
        IF = self._check_flag_bit(9)
        DF = self._check_flag_bit(10)
        OF = self._check_flag_bit(11)
        IOPL = (val >> 12) & 0b11
        NT = self._check_flag_bit(14)
        RF = self._check_flag_bit(16)
        VM = self._check_flag_bit(17)
        AC = self._check_flag_bit(18)
        VIF = self._check_flag_bit(19)
        VIP = self._check_flag_bit(20)
        ID = self._check_flag_bit(21)

        if CF:
            infol.append('CF')
        if PF:
            infol.append('PF')
        if AF:
            infol.append('AF')
        if ZF:
            infol.append('ZF')
        if SF:
            infol.append('SF')
        if TF:
            infol.append('TF')
        if IF:
            infol.append('IF')
        if DF:
            infol.append('DF')
        if OF:
            infol.append('OF')
        infol.append(f'IOPL={IOPL}')
        if NT:
            infol.append('NT')
        if RF:
            infol.append('RF')
        if VM:
            infol.append('VM')
        if AC:
            infol.append('AC')
        if VIF:
            infol.append('VIF')
        if VIP:
            infol.append('VIP')
        if ID:
            infol.append('ID')

        return "[" + " ".join(infol) + "]"



@dataclass
class Registers:
    al: RegisterDescriptor
    ax: RegisterDescriptor
    eax: RegisterDescriptor
    rax: RegisterDescriptor
    bl: RegisterDescriptor
    bx: RegisterDescriptor
    ebx: RegisterDescriptor
    rbx: RegisterDescriptor
    cl: RegisterDescriptor
    cx: RegisterDescriptor
    ecx: RegisterDescriptor
    rcx: RegisterDescriptor
    dl: RegisterDescriptor
    dx: RegisterDescriptor
    edx: RegisterDescriptor
    rdx: RegisterDescriptor

    esi: RegisterDescriptor
    rsi: RegisterDescriptor
    edi: RegisterDescriptor
    rdi: RegisterDescriptor
    rbp: RegisterDescriptor
    ebp: RegisterDescriptor

    esp: RegisterDescriptor
    rsp: RegisterDescriptor
    r8: RegisterDescriptor
    r9: RegisterDescriptor
    r10: RegisterDescriptor
    r11: RegisterDescriptor
    r12: RegisterDescriptor
    r13: RegisterDescriptor
    r14: RegisterDescriptor
    r15: RegisterDescriptor

    r8d: RegisterDescriptor
    r9d: RegisterDescriptor
    r10d: RegisterDescriptor
    r11d: RegisterDescriptor
    r12d: RegisterDescriptor
    r13d: RegisterDescriptor
    r14d: RegisterDescriptor
    r15d: RegisterDescriptor

    eflags: EFLAGSRegisterDescriptor
    rip: RegisterDescriptor

    @classmethod
    def create(cls):
        reg_dict = {}
        for reg_name in Registers.__dataclass_fields__.keys():
            reg_dict[reg_name] = Registers.__dataclass_fields__[reg_name].type(reg_name)
        x = Registers(**reg_dict)
        return x

    def dump(self):
        return {reg_name: self.__dict__[reg_name].__get__(self) for reg_name in Registers.__dataclass_fields__.keys()}

    def hexdump(self):
        reg_dict = self.dump()
        for reg in reg_dict.keys():
            print(reg, hex(reg_dict[reg]), self.__dict__[reg].info())

    def restore(self, reg_dump):
        for reg_name in reg_dump.keys():
            set_reg(reg_name, reg_dump[reg_name])

    def __getattribute__(self, attr):
        obj = object.__getattribute__(self, attr)
        if hasattr(obj, '__get__'):
                return obj.__get__(self, type(self))
        return obj

    # TODO(ju256): refactor
    def __setattr__(self, attr, value):
        # hacky way to check whether we setup the Registers object here with attr iE RegisterDescriptor
        # or if this is actually user invoked e.g. registers.rax = 1337
        if isinstance(value, RegisterDescriptor):
            object.__setattr__(self, attr, value)
        else:
            if not isinstance(value, int):
                raise ValueError(f"Invalid value in register setter: {value}")
            obj = object.__getattribute__(self, attr)
            if hasattr(obj, '__set__'):
                return obj.__set__(self, value)
            else:
                raise ValueError(f"__set__ not found on {obj}")


registers = Registers.create()
