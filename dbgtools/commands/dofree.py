import gdb
from dbgtools.commands.utils import SupressedOutput, parse_tint
from dbgtools.main import *


class DoFreeCmd(gdb.Command):
    """Performs free(ptr)"""
    def __init__(self):
        super(DoFreeCmd, self).__init__("dofree", gdb.COMMAND_USER)

    def invoke(self, argument, from_tty):
        argument = argument.split()
        if len(argument) != 1:
            self.help()
        else:
            ptr = parse_tint(argument[0])
            try:
                self._do_free(ptr)
            except ValueError:
                print("Address of free could not be found. Please specify it"
                      + " manually!")

    def _do_free(self, ptr: int):
        with SupressedOutput():
            free_addr = get_free_addr()
            call_func1(free_addr, ptr)
        gdb.execute(f"x/4gx {hex(ptr)}")
        
    def help(self):
        print("Usage: dofree <ptr> [<ptr to free function>]")
