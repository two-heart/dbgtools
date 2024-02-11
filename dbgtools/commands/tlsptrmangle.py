import pwndbg
import argparse
import pwndbg.commands
from typing import Optional
from dbgtools.tls import tls_ptr_mangling_cookie, tls_ptr_mangle, tls_ptr_demangle


parser = argparse.ArgumentParser(description="Print tls ptr mangling cookie")
parser.add_argument("ptr", type=int, nargs='?', help="ptr to mangle/demangle")
parser.add_argument("--mangle", action="store_true", help="mangle ptr instead of demangling")


@pwndbg.gdblib.proc.OnlyWhenRunning
@pwndbg.commands.ArgparsedCommand(parser)
def tlsptrmangle(ptr: Optional[int], mangle: bool = False):
    print(f"tls PTR_MANGLE cookie: {hex(tls_ptr_mangling_cookie())}")
    if ptr is not None:
        if mangle:
            print(f"mangled ptr: {hex(tls_ptr_mangle(ptr))}")
        else:
            print(f"demangled ptr: {hex(tls_ptr_demangle(ptr))}")
