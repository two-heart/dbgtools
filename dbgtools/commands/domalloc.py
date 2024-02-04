import gdb
from dbgtools.commands.utils import SupressedOutput, parse_tint
from dbgtools.main import get_malloc_addr, call_func1

class DoMallocCmd(gdb.Command):
    """Performs malloc(size)"""
    def __init__(self):
        super(DoMallocCmd, self).__init__("domalloc", gdb.COMMAND_USER)

    def invoke(self, argument, from_tty):
        argument = argument.split()
        if len(argument) != 1:
            self.help()
        else:
            size = parse_tint(argument[0])
            try:
                self._do_malloc(size)
            except ValueError:
                print("Address of malloc could not be found. Please specify it manually!")

    def _do_malloc(self, size: int):
        with SupressedOutput():
            malloc_addr = get_malloc_addr()
            malloc_chunk = call_func1(malloc_addr, size)
        gdb.execute(f"x/{(size//8)+1}gx {hex(malloc_chunk)}")
        print(f"malloc({hex(size)}) -> {hex(malloc_chunk)}")

    def help(self):
        print("Usage: domalloc <size> [<ptr to malloc function>]")
