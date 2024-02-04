import gdb
from dbgtools.main import *

class MmapCmd(gdb.Command):
    """Create a mmap'ed memory region"""
    def __init__(self):
        super(MmapCmd, self).__init__("mmap", gdb.COMMAND_USER)

    def help(self):
        print("mmap (<protections>)")

    def invoke(self, argument, from_tty):
        argument = argument.split()
        if len(argument) >= 2:
            self.help()
            return
        elif len(argument) == 1:
            protection_str = argument[0]
            protections = 0
            for c in protection_str:
                if c.lower() not in "rwx":
                    print(f"{c} is not in 'rwx'")
                else:
                    protections |= {'r': PROT_READ, 'w': PROT_WRITE, 'x': PROT_EXEC}[c]
        else:
            protections = PROT_READ | PROT_WRITE | PROT_EXEC
            protection_str = "RWX"

        mmap_ptr = mmap(protect = protections)
        print(f"{protection_str.upper()} page @ {hex(mmap_ptr)}")
