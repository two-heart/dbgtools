import gdb
import argparse
import pwndbg
import pwndbg.commands
from dbgtools.commands.utils import SupressedOutput, parse_tint
from dbgtools.main import get_malloc_addr, call_func1

parser = argparse.ArgumentParser(description="Performs malloc(size)")
parser.add_argument("size", type=int, help="size")


@pwndbg.gdblib.proc.OnlyWhenRunning
@pwndbg.commands.ArgparsedCommand(parser)
def domalloc(size):
    try:
        with SupressedOutput():
            malloc_addr = get_malloc_addr()
            malloc_chunk = call_func1(malloc_addr, size)
        gdb.execute(f"x/{(size//8)+1}gx {hex(malloc_chunk)}")
        print(f"malloc({hex(size)}) -> {hex(malloc_chunk)}")
    except ValueError:
        print("Address of malloc could not be found. Please specify it manually!")
