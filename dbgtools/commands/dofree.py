import argparse
import pwndbg
import pwndbg.commands
from dbgtools.commands.utils import SupressedOutput, parse_tint
from dbgtools.functions import free
from dbgtools.gdbapi import execute_command


parser = argparse.ArgumentParser(description="Performs free(ptr)")
parser.add_argument("ptr", type=int, help="ptr to free")

@pwndbg.gdblib.proc.OnlyWhenRunning
@pwndbg.commands.ArgparsedCommand(parser)
def dofree():
    try:
        with SupressedOutput():
            free(ptr)
        execute_command(f"x/4gx {hex(ptr)}")
    except ValueError:
        print("Address of free could not be found.")
