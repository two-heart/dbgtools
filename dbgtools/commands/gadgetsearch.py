import gdb
from dbgtools.memory import read_bytes
import pwn


class GadgetSearchCmd(gdb.Command):
    """In memory search for (ROP) gadgets"""
    def __init__(self):
        super(GadgetSearchCmd, self).__init__("gadgetsearch", gdb.COMMAND_USER)

    def help(self):
        print("gadgetsearch <gadget_str>")

    def invoke(self, args, from_tty):
        argstr = args.strip('"').strip()
        b = pwn.asm(argstr)
        print(f"Searching for {str(b).lstrip('b')}")
        for page in sorted(get_executable_pages(), key=lambda p: p.start):
            for ptr in range(page.start, page.end + 1):
                if read_bytes(ptr, len(b)) == b:
                    offset = ptr - page.start
                    print(f"{argstr} @ {page.objfile}+{hex(offset)} ({hex(ptr)})")
