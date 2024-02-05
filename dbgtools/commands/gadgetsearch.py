import gdb
import pwndbg
import argparse
import pwndbg.commands
from dbgtools.memory import read_bytes
from dbgtools.main import get_executable_pages
import pwn


parser = argparse.ArgumentParser(description="In memory search for (ROP) gadgets")
parser.add_argument("gadget", type=int, help="Gadget string")

@pwndbg.gdblib.proc.OnlyWhenRunning
@pwndbg.commands.ArgparsedCommand(parser)
def gadgetsearch(gadget: str):
    b = pwn.asm(gadget)
    print(f"Searching for {str(b).lstrip('b')}")
    for page in sorted(get_executable_pages(), key=lambda p: p.start):
        for ptr in range(page.start, page.end + 1):
            if read_bytes(ptr, len(b)) == b:
                offset = ptr - page.start
                print(f"{gadget} @ {page.objfile}+{hex(offset)} ({hex(ptr)})")
