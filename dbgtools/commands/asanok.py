import gdb
from dbgtools.asan import asan_ok
from dbgtools.commands.utils import parse_tint


class ASANOKCmd(gdb.Command):
    """Check if ptr is in ASAN redzone"""
    def __init__(self):
        super(ASANOKCmd, self).__init__("asanok", gdb.COMMAND_USER)

    def help(self):
        print("asanok <ptr>")

    def invoke(self, args, from_tty):
        args = args.split()
        if len(args) != 1:
            self.help()
            return
        else:
            ptr = parse_tint(args[0])
            aok = asan_ok(ptr)
            if aok:
                print(f"Writing to {hex(ptr)} allowed")
            else:
                print(f"Writing to {hex(ptr)} forbidden")
