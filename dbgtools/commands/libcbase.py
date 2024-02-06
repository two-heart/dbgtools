import pwndbg
import argparse
import pwndbg.commands
from dbgtools.main import get_libc_base
from dbgtools.commands.utils import parse_tint

# TODO(liam) I belief pwndbg by now support this
# if this is true and better, depricate this command

parser = argparse.ArgumentParser(description="Looks up the libc base address")
parser.add_argument("ptr", type=int, nargs='?', default=0, help="get offset to this pointer from libcbase")

@pwndbg.gdblib.proc.OnlyWhenRunning
@pwndbg.commands.ArgparsedCommand(parser)
def libcbase(ptr: int = 0):
    libc_base = get_libc_base()
    if libc_base is None:
        print("libc base not found")
    elif ptr == 0:
        print(f"libc @ {hex(libc_base)}")
    else:
        print(f"libc @ {hex(libc_base)} | off: {hex(ptr - libc_base)}")
