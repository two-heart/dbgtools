import pwndbg
import argparse
import pwndbg.commands
from dbgtools.main import force_load_pie_base, get_pie_base
from dbgtools.gdbapi import set_breakpoint
from dbgtools.commands.utils import parse_tint


# Works before program start which is not supported by pwndbg
parser = argparse.ArgumentParser(description="Creates a breakpoint relative to the current PIE base.")
parser.add_argument("offset", type=int, help="offset to pie base")

@pwndbg.commands.ArgparsedCommand(parser)
def bpie(offset: int):
    piebase = get_pie_base()
    if piebase is None:
        # program not running probably
        print("Current PIE base could not be found.\n" +
                    "Do you want to try and force PIE base loading (program will be executed!)")
        choice = input("[y/n] > ")
        if len(choice) >= 1 and choice[0].lower() == "y":
            piebase = force_load_pie_base()
            if piebase is None:
                print("Could not force load PIE base")
                return
        else:
            return

    set_breakpoint(piebase + offset)
