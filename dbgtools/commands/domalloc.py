import argparse
import pwndbg
import pwndbg.commands
from dbgtools.commands.utils import SupressedOutput
from dbgtools.functions import malloc
from dbgtools.gdbapi import execute_command


parser = argparse.ArgumentParser(description="Performs malloc(size)")
parser.add_argument("size", type=int, help="size")

@pwndbg.gdblib.proc.OnlyWhenRunning
@pwndbg.commands.ArgparsedCommand(parser)
def domalloc(size):
    try:
        with SupressedOutput():
            malloc_chunk = malloc(size)
        execute_command(f"x/{(size//8)+1}gx {hex(malloc_chunk)}")
        print(f"malloc({hex(size)}) -> {hex(malloc_chunk)}")
    except ValueError:
        print("Address of malloc could not be found.")
