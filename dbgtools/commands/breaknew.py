import pwndbg
import argparse
import pwndbg.commands
from dbgtools.gdbapi import execute_command, delete_all_breakpoints


parser = argparse.ArgumentParser(description="Creates a breakpoint and delete all previous ones")
parser.add_argument("bp", type=str, help="breakpoint string")

@pwndbg.commands.ArgparsedCommand(parser)
def bnew(bp: str):
    delete_all_breakpoints()
    # TODO(ju256): refactor for general bp interface that
    # can handle *bp as well
    execute_command(f"b {bp}")
