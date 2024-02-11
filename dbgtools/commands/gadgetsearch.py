import pwndbg
import argparse
import pwndbg.commands
from dbgtools.memory import read_bytes
from dbgtools.main import get_executable_pages, find_gadget
import pwn


parser = argparse.ArgumentParser(description="In memory search for (ROP) gadgets")
parser.add_argument("gadget", type=str, help="Gadget string")


@pwndbg.gdblib.proc.OnlyWhenRunning
@pwndbg.commands.ArgparsedCommand(parser)
def gadgetsearch(gadget: str):
    b = pwn.asm(gadget, arch="amd64", os="linux")
    print(f"Searching for {str(b).lstrip('b')}")
    for (page, offset) in find_gadget(b):
        ptr = page.start + offset
        print(f"{gadget} @ {page.objfile}+{hex(offset)} ({hex(ptr)})")
