import argparse
import pwndbg
import pwndbg.commands
from dbgtools.asan import visualize_region


parser = argparse.ArgumentParser(description="Visualize asan redzones")
parser.add_argument("ptr", type=int, help="ptr to check surronding region")

@pwndbg.gdblib.proc.OnlyWhenRunning
@pwndbg.commands.ArgparsedCommand(parser)
def asanviz(ptr: int):
    visualize_region(ptr)
