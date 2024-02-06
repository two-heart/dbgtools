import argparse
import pwndbg
import pwndbg.commands
from typing import Optional
from dbgtools.v8 import v8heap_page, v8heap_start_addr
from dbgtools.commands.utils import parse_tint


parser = argparse.ArgumentParser(description="Show V8 heap address")
parser.add_argument("--ptr", type=int, help="Calculate offset from pointer to v8 heap")
parser.add_argument("--offset", type=int, help="Offset from v8 heap")


@pwndbg.gdblib.proc.OnlyWhenRunning
@pwndbg.commands.ArgparsedCommand(parser)
def v8_heap(ptr: Optional[int] = None, offset: Optional[int] = None):
        v8_heap_page_obj = v8heap_page()
        v8_heap_addr = v8heap_start_addr()
        if v8_heap_addr == -1:
            print("V8 heap not found")
            return
        else:
            if ptr is None and offset is None:
                print(f"V8 heap @ {hex(v8_heap_addr)}")
            elif offset is not None:
                print(f"V8 heap+{hex(offset)} @ {hex(v8_heap_addr+offset)}")
            else:
                if ptr >= v8_heap_page_obj.end:
                    print("ptr does not seem to be on V8 heap")
                else:
                    print(f"V8 heap offset @ {hex(ptr - v8_heap_addr)}")
