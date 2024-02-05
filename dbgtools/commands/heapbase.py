import gdb
import pwndbg
import argparse
import pwndbg.commands
from dbgtools.main import get_heap_base
from typing import Optional


parser = argparse.ArgumentParser(description="Looks up the base address of all existing heaps")
parser.add_argument("--ptr", type=int, help="ptr to calculate difference to heap base")

@pwndbg.gdblib.proc.OnlyWhenRunning
@pwndbg.commands.ArgparsedCommand(parser)
def heapbase(ptr: Optional[int] = None):
    heap_addresses = get_heap_base()
    if heap_addresses is None:
        print("no heap found")
    elif len(heap_addresses) == 1 and heap_addresses[0] != -1:
        heap_ptr = heap_addresses[0]
        if ptr is not None:
            print(f"heap @ {hex(heap_ptr)} | off: {hex(ptr - heap_ptr)}")
        else:
            print(f"heap @ {hex(heap_ptr)}")
    elif len(heap_addresses) >= 2:
        print("Found multiple heaps")
        for hp in heap_addresses:
            print(f"heap @ {hex(hp)}")
