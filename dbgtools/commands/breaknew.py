import gdb
import pwndbg
import argparse
import pwndbg.commands
from dbgtools.main import delete_all_breakpoints
from dbgtools.gdbapi import execute_commands


parser = argparse.ArgumentParser(description="Creates a breakpoint and delete all previous ones")
parser.add_argument("bp", type=str, help="breakpoint string")

@pwndbg.commands.ArgparsedCommand(parser)
def bnew(bp: str):
    delete_all_breakpoints()
    execute_commands([f"b {bp}"])
