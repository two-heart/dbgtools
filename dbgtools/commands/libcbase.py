import gdb
from dbgtools.main import get_libc_base
from dbgtools.commands.utils import parse_tint

# TODO(liam) I belief pwndbg by now support this
# if this is true and better, depricate this command

class LibcBaseCmd(gdb.Command):
    """Looks up the libc base address"""
    def __init__(self):
        super(LibcBaseCmd, self).__init__("libcbase", gdb.COMMAND_USER)

    def invoke(self, argument, from_tty):
        argument = argument.split()
        if len(argument) != 1 and len(argument) != 0:
            self.help()
        else:
            libc_base = get_libc_base()
            if libc_base is None:
                print("libc base not found")
            elif len(argument) == 0:
                print(f"libc @ {hex(libc_base)}")
                return
            else:
                ptr = parse_tint(argument[0])
                print(f"libc @ {hex(libc_base)} | off: {hex(ptr - libc_base)}")
                
    def help(self):
        print("Usage: libcbase [<ptr>]")
