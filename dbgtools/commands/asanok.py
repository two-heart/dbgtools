import pwndbg
import argparse
import pwndbg.commands
from dbgtools.asan import asan_ok


parser = argparse.ArgumentParser(description="Check if ptr is in ASAN redzone")
parser.add_argument("ptr", type=int, help="ptr to check")

@pwndbg.gdblib.proc.OnlyWhenRunning
@pwndbg.commands.ArgparsedCommand(parser)
def asanok(ptr: int):
    aok = asan_ok(ptr)
    if aok:
        print(f"Writing to {hex(ptr)} allowed")
    else:
        print(f"Writing to {hex(ptr)} forbidden")
