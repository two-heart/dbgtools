from dbgtools.commands.utils import parse_tint, SupressedOutput
from dbgtools.main import *


class MprotectCmd(gdb.Command):
    """mprotect memory region at ptr"""
    def __init__(self):
        super(MprotectCmd, self).__init__("mprotect", gdb.COMMAND_USER)

    def help(self):
        print("mprotect <addr> <protections>")

    def invoke(self, argument, from_tty):
        argument = argument.split()
        if len(argument) != 2:
            self.help()
        else:
            addr = parse_tint(argument[0])
            protection_str = argument[1]
            protections = 0
            for c in protection_str:
                if c.lower() not in "rwx":
                    print(f"{c} is not in 'rwx'")
                else:
                    protections |= {'r': PROT_READ,
                                    'w': PROT_WRITE,
                                    'x': PROT_EXEC}[c]
            with SupressedOutput():
                mprotect(address=addr, prot=protections)
                gdb.execute(f"vmmap {hex(addr)}")
