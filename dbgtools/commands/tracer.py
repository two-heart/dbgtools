import gdb
import time
import pwndbg
import argparse
import pwndbg.commands
from dbgtools import is_program_running
from dbgtools.gdbapi import run, cont, set_breakpoint, set_watchpoint,\
    delete_all_breakpoints, si, execute_command
from dbgtools.regs import *
from dbgtools.logger import Logger
from typing import Optional


# TODO(ju256): pretty bad refactor
class Tracer:
    def __init__(self, trace_end_addr=None, start_bp_addr=None, start_wp_addr=None, force_rerun=True, start_args=None, timeout=60):
        self._trace_end_addr = trace_end_addr
        self._start_bp_addr = start_bp_addr
        self._start_wp_addr = start_wp_addr
        self._force_rerun = force_rerun
        self._start_args = start_args
        self._timeout = timeout
        self._start_time = None

        if self._start_bp_addr is None and self._start_wp_addr is None:
            raise ValueError("Tracer needs atleast start breakpoint or start watchpoint")

    @classmethod
    def get_from_watchpoint(cls, wp_addr, trace_end_addr=None, force_rerun=True, start_args=None, timeout=60):
        return Tracer(start_wp_addr=wp_addr, trace_end_addr=trace_end_addr, force_rerun=force_rerun, start_args=start_args, timeout=timeout)

    @classmethod
    def get_from_breakpoint(cls, bp_addr, trace_end_addr=None, force_rerun=True, start_args=None, timeout=60):
        return Tracer(start_bp_addr=bp_addr, trace_end_addr=trace_end_addr, force_rerun=force_rerun, start_args=start_args, timeout=timeout)

    def start(self):
        if self._start_bp_addr is not None:
            set_breakpoint(self._start_bp_addr)
        elif self._start_wp_addr is not None:
            set_watchpoint(self._start_wp_addr)

        self._start_time = time.time()
        if self._force_rerun:
            run(self._start_args)
        else:
            print("jo")
            print(registers.rdi)
            print(is_program_running())
            if is_program_running():
                cont()
            else:
                run(self._start_args)

        # wait for breakpoint or watchpoint hit
        logger = Logger()
        logger.clear_log_file()
        while True:
            try:
                time_ran = (time.time() - self._start_time)
                if time_ran >= self._timeout:
                    print("[Tracer] Hit timeout")
                    break
                # TODO(liam) check if may be null
                log = gdb.execute("x/i $rip", to_string=True)
                if log is None:
                    log = "<unknown>"
                log = log.encode().lstrip(b"=> ").rstrip()
                if len(log) != 0:
                    logger.log_line(b"[Tracer] " + log)
                if self._trace_end_addr is not None and registers.rip == self._trace_end_addr:
                    break
                si()
                # TODO(ju256): use this again if possible
                # dont remember when this broke
                # execute_command("s")
            except gdb.error:
                # TODO(ju256): shit way to stop here. refactor
                break

        logger.print_log()
        logger.write_log_to_log_file()


parser = argparse.ArgumentParser(description="Traces instructions")
parser.add_argument("--watchpoint", action='store_true', help="start tracing from a watchpoint")
parser.add_argument("--breakpoint", action='store_true', help="start tracing from a breakpoint")
parser.add_argument("ptr", type=int, help="watch/breakpoint string")
parser.add_argument("--end", type=int, help="stop tracing when this address is hit")
parser.add_argument("--force-rerun", action='store_true', help="force a rerun the program")



@pwndbg.gdblib.proc.OnlyWhenRunning
@pwndbg.commands.ArgparsedCommand(parser)
def tracer(watchpoint: bool, breakpoint: bool, ptr: int, end: Optional[int] = None, force_rerun: bool = False):
    if (not watchpoint and not breakpoint) or (watchpoint and breakpoint):
        raise ValueError("Either --watchpoint or --breakpoint need to be specified")
    else:
        delete_all_breakpoints()
        if watchpoint:
            t = Tracer.get_from_watchpoint(ptr, trace_end_addr=end, force_rerun=force_rerun)
        else:
            t = Tracer.get_from_breakpoint(ptr, trace_end_addr=end, force_rerun=force_rerun)
        t.start()
