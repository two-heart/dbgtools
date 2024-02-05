import gdb
import argparse
import pwndbg
import pwndbg.commands
from dbgtools.commands.utils import SupressedOutput, parse_tint
from dbgtools.main import *


parser = argparse.ArgumentParser(description="Performs free(ptr)")
parser.add_argument("ptr", type=int, help="ptr to free")

@pwndbg.gdblib.proc.OnlyWhenRunning
@pwndbg.commands.ArgparsedCommand(parser)
def dofree():
    try:
        with SupressedOutput():
            free_addr = get_free_addr()
            call_func1(free_addr, ptr)
        gdb.execute(f"x/4gx {hex(ptr)}")
    except ValueError:
        print("Address of free could not be found. Please specify it"
              + " manually!")
