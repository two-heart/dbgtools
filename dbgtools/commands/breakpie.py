import gdb
from dbgtools.main import force_load_pie_base, get_pie_base, \
                          set_manual_breakpoint
from dbgtools.commands.utils import parse_tint


class BreakPIECmd(gdb.Command):
    """
    Creates a breakpoint relative to the current PIE base.

    While this is supported by pwndbg, we want to keep it because it works
    before program start.
    """
    def __init__(self):
        super(BreakPIECmd, self).__init__("bpie", gdb.COMMAND_USER)

    def help(self):
        print("Usage: bpie <relative bp offset>")

    def invoke(self, argument, from_tty):
        argument = argument.split()
        if len(argument) != 1:
            self.help()
        else:
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

            bp_off = parse_tint(argument[0])
            set_manual_breakpoint(piebase + bp_off)
