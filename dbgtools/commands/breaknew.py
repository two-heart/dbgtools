import gdb
from dbgtools.main import delete_all_breakpoints
from dbgtools.gdbapi import execute_commands


class BreakNewCmd(gdb.Command):
    """Creates a breakpoint and delete all previous ones"""
    def __init__(self):
        super(BreakNewCmd, self).__init__("bn", gdb.COMMAND_USER)

    def help(self):
        print("Usage: bn <bp>")

    def invoke(self, argument, from_tty):
        argument = argument.split()
        if len(argument) != 1:
            self.help()
        else:
            delete_all_breakpoints()
            execute_commands([f"b {argument[0]}"])
